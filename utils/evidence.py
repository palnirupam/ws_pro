from dataclasses import dataclass, field
from typing import Any, Dict, Optional

@dataclass
class Evidence:
    """Stores proof and reproduction steps for a vulnerability finding."""
    proof: str = 'Evidence pending'
    payload: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    reproduce: Optional[str] = None
    _extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def make(cls, **kwargs):
        """Helper to construct Evidence with extra fields."""
        extra = {}
        for k in list(kwargs.keys()):
            if k not in ['proof', 'payload', 'request', 'response', 'reproduce']:
                extra[k] = kwargs.pop(k)
        
        evidence = cls(**kwargs)
        evidence._extra = extra
        return evidence

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation, omitting empty fields."""
        d = {}
        if self.proof:
            d['proof'] = self.proof
        if self.payload: d['payload'] = self.payload
        if self.request: d['request'] = self.request
        if self.response: d['response'] = self.response
        if self.reproduce: d['reproduce'] = self.reproduce
        d.update(self._extra)
        return d
