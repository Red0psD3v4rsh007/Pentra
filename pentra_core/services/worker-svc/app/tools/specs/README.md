# Pentra Worker — Tool Specifications
#
# Each YAML file in this directory defines one security tool.
# The tool_registry loads all specs at startup.
#
# Schema:
#   name: str             # Must match ToolSpec.name in dag_builder
#   worker_family: str    # recon | network | web | vuln | exploit
#   image: str            # Docker image to run
#   command: list[str]    # Command template (use {target}, {output_dir}, {config_file})
#   output_parser: str    # json | xml_nmap | csv | raw | scope
#   artifact_type: str    # subdomains | hosts | services | endpoints | vulnerabilities | etc.
#   default_timeout: int  # seconds
#   env_vars: dict        # optional extra env vars for the container
