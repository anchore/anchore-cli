# Changelog

## v0.9.1
+ Added - Support for exclusion selectors in analysis-archive rules in the add/update command
+ Added - Support for "Max Images Per Account" setting in analysis-archive rule creation 
+ Added - Support for Anchore Enterprise False Positive management feature to add/list/remove artifact corrections.
+ Improved - Update to use UBI 8.3 base image for Docker image instead of UBI 8.2. Fixes #163 
+ Improved - Update PyYAML version from 5.3.1 to 5.4.1. Fixes #155
+ Fixed - Event list filtering by level fixed to correctly support the filters. Fixes #141
+ Fixed - Corrected archive get and delete command help. Fixes #142
+ Fixed - Remove wait for disabled group records in a feed or disabled feedss for system wait

## v0.9.0
+ Added - Webhook test command against Engine API to test webhook configurations. Fixes #109
+ Added - Repository add dry-run command to show how many tags would be added if the full repository were scanned. Fixes #99
+ Added - Additional subscription listing and display command options including subscription deletion. Fixes #88
+ Improved - Update Docker image to use python 3.8. Fixes #121


## v0.8.2 (2020-10-09)
+ Fix - Update urllib to 1.25.9 to remove and future exposure to CVE-2020-26316
+ Improved - improved handling of service states during system bootstrap when versions may not be available
+ Improved - improved help messages for analysis archive 'add' command and content types

