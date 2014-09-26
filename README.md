moodle-dict-attack-dropper
==========================

Somebody hammering your Moodle? Try vanishing.

This script checks your ```mdl_log``` table for repeated authentication failures. When any client IP surpasses your threshold for failures, this script adds IPTABLES rules to drop all their packets.

IPTABLES will be reset when you reboot, unless you preserve these changes somehow. (I don't preserve them.)

1. Copy ```config-dist.py``` to ```config.py``` and make sure it's in the same directory as ```moodle-dict-attack-dropper.py```.
2. Edit config.py and fill in your information. (Most of the fields should probably just match your moodle's config.php.)
3. Set moodle-dict-attack-dropper.py up to run regularly via cron. Example (running as root): ```*/5 * * * * /path/to/your/moodle-dict-attack-dropper.py```
