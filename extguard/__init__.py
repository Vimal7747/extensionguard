# extguard - ExtensionGuard: browser-extension supply chain threat detection
#
# Command-line entry points (installed by pip):
#   extguard            pre-install scanner        (extguard.main)
#   extguard-monitor    Stage 3 CDP monitor        (extguard.behavioral_monitor)
#   extguard-dispatch   Stage 4 alert dispatch     (extguard.alert_dispatcher)
#   extguard-remediate  Stage 5 remediation        (extguard.remediation)
#   extguard-dashboard  analyst web console        (extguard.dashboard)
#   extguard-ttp-sync   threat-intel sync          (extguard.ttp_ingestor)
#   extguard-sigma      Sigma rule export          (extguard.sigma_generator)
#
# `python -m extguard <file>` is the same as `extguard <file>`.

try:
    from importlib.metadata import PackageNotFoundError, version

    __version__ = version("extensionguard")
except PackageNotFoundError:  # running from a source checkout without pip install
    __version__ = "0.0.0+source"
