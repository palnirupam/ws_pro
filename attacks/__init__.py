# Attack modules — injection, auth, network, timing, subprotocol,
#                  race_condition, ssrf, ssti, mass_assignment, business_logic
from attacks.race_condition  import test_race_condition
from attacks.ssrf            import test_ssrf
from attacks.ssti            import test_ssti
from attacks.mass_assignment import test_mass_assignment
from attacks.business_logic  import test_business_logic
