You are designing the Asset Discovery section for a PQC security scanner dashboard.
Build a complete spec for this section, including:

- Purpose and user goals (what problem it solves, what actions users take)
- Data model fields (id, hostname, IP, OS, status, risk score, last seen, owner, tags)
- UI components:
  - top toolbar: search, filter, sort, refresh, date range
  - data table + columns + row actions (inspect, map, export, archive)
  - map view toggle (topology or geo mode)
  - expanded detail panel / side drawer
  - pagination/infinite scroll and empty state
- Behavior:
  - real-time updates on network scan events
  - selected asset drill-down / relationship graph
  - role-based visibility for Admin/Manager/Viewer
  - “Rotate API key” UX hint in profile area (non-functional placeholder)
- Accessibility and responsive layout:
  - top header nav with full breadcrumbs and action links
  - mobile stacked mode, no sidebar on small screens

Output:
- one textual “Asset Discovery Section” spec (short doc)
- quick component breakdown (list with targets)
- simple copy for header + CTA
asset discovery page should have a tabbed interface with tabs for domains, SSL certificates, IP addresses, and software. Each tab should display a table with relevant information for that category, such as domain name, certificate details, IP address, or software name and version. The page should also include filters and search functionality for each category, as well as clear calls to action for promoting discovered items to the asset inventory. For empty states, display messages like "No domains discovered yet. Run a scan to find new assets." The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility.
 The design should be consistent with the modern dark glassmorphism style used throughout the application. anything in the table should be clickable to view more details about the asset. asset discovery page should have ip to location mapping with openstreet map component which should show the location of discovered ip addresses on the map. The page should also include a section for recent discoveries, listing items that were discovered in the last 7 days, along with their name, type, discovery date, and risk score. The overall design should prioritize readability and accessibility while maintaining a modern dark glassmorphism aesthetic. also sould have a network mapping, asset discovery should also track details like detection date product name, version, associated assets, and risk score for software discoveries. The design should maintain the modern dark glassmorphism aesthetic while ensuring strong readability and accessibility. The network mapping should visually represent the relationships between discovered assets, showing how they are connected within the network. This could be implemented using a graph visualization library, allowing users to easily understand the structure of their asset network and identify potential vulnerabilities or points of interest. The design should prioritize clarity and usability while maintaining the overall aesthetic of the application. network mapping and topology shoud visualize relation between assets and how they are connected in the network, showing details like asset name, and ip related to that mapping and topology.