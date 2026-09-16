# Public-source capability research

Checked 2026-09-16 against official provider documentation. Platform access, pricing and terms drift; revalidate before enabling or expanding any collector.

| Source | Official API | Public data available | Auth / rate / cost | Restrictions | MVP status |
| --- | --- | --- | --- | --- | --- |
| Manual JSON/CSV / Instagram export ZIP | Local importer | Operator-supplied entities, relationships and Instagram account-owner connections | Standalone Social Graph session; local limits; no provider cost | Operator must have a lawful basis; ZIP works only for the exporting account | **SUPPORTED** |
| GitHub | REST API | Public user profile, followers/following, organizations, repositories, public events and contributor metadata where exposed | Token optional; 60 requests/hour unauthenticated and normally 5,000/hour authenticated; secondary limits also apply | Public-only; response availability and event retention vary | **SUPPORTED** |
| Website/domain | Standard HTTP(S) | HTML title/description, obvious links, social links and published contact links | No shared API; site-specific policies | Shallow collection only; no auth bypass; SSRF/size/time/page controls | **SUPPORTED** |
| Instagram | Meta APIs for professional accounts; optional Apify provider adapter | Official API: professional metadata/counts/media. Provider: best-effort public follower/following identities | Meta app review for official APIs; separate Apify token and per-result cost for provider | No official arbitrary follower/following identity-list endpoint; provider is non-official, can drift/fail and needs separate terms/privacy review | **PARTIAL / PROVIDER-DEPENDENT** |
| Telegram | Telegram API/TDLib/MTProto and Bot API | Public channel/supergroup content and metadata as permitted | Telegram app/bot credentials and method-specific limits | Participant lists may be hidden; access and privacy settings matter; no broad identity graph promised | **NOT SUPPORTED** |
| X | X API | User lookup and follower/following resources in approved products | Pay-per-use; current resource pricing and endpoint rate limits apply | Paid usage, caps and developer policy make it a deliberate later integration | **NOT SUPPORTED** |
| LinkedIn | LinkedIn APIs | Authenticated member basics and approved organization/marketing data | OAuth, product access and app review | Not an arbitrary public profile/network collection API; organization operations are role/permission constrained | **NOT SUPPORTED** |
| TikTok | Research Tools / Research API | Public account/video and follower/following data for approved research access | Eligible approved researchers; quotas documented per endpoint/product | Access is limited to qualifying non-profit research and approved regions/uses | **NOT SUPPORTED** |

## GitHub collector

The collector uses only GitHub's official REST resources documented under [REST API endpoints for users](https://docs.github.com/en/rest/users) and [REST API endpoints for activity](https://docs.github.com/en/rest/activity). It collects a seed profile plus bounded followers, following, organizations, repositories and public events, storing each API or web resource URL as provenance. The official [REST rate-limit documentation](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) states 60 primary requests per hour for unauthenticated requests and normally 5,000 per hour for authenticated users, alongside secondary limits. The collector exposes the remaining-limit header, uses a timeout and caps expansion at two hops.

## Instagram decision

Meta's current [Instagram API with Instagram Login documentation](https://www.postman.com/meta/workspace/instagram/documentation/23987686-9386f468-7714-490f-9bfc-9442db5c8f00) targets Instagram professional accounts (businesses and creators) and their authorised management workflows. The [Facebook Login / Business Discovery collection](https://www.postman.com/meta/instagram/folder/u4g5a2a/instagram-api-with-facebook-login) documents discovery of limited metadata for other professional accounts. These official surfaces do not provide arbitrary public consumer profiles' follower/following identity lists.

The service therefore does not pretend that Meta supplies these lists. It can optionally invoke a separately configured [Apify Actor](https://apify.com/zaver.api/instagram-followers-scraper) through Apify's [official Actor API](https://docs.apify.com/api/v2). Apify supports bearer-token authentication and synchronous dataset results. This adapter is third-party, non-official and best-effort: it is disabled without a token, capped by node/result/cost/time limits, never receives Instagram credentials, discards contact enrichment and stores provider provenance with `confidence=0.9`. A failure or partial direction is exposed explicitly.

The no-cost supported alternative is an account-owner export from Meta Accounts Center. The operator selects only Followers and following in JSON format and uploads the ZIP; the service reads the official `followers*.json` and `following.json` records without storing or executing the archive, and marks each resulting `FOLLOWS` relationship as direct platform-export evidence with `confidence=1`. This is not automatic remote collection and cannot obtain another person's export. Self-hosted Instaloader was evaluated but not integrated: follower/following access requires a logged-in Instagram session, uses undocumented interfaces, can trigger checkpoints/rate limits, and conflicts with the MVP rule against accepting Instagram passwords or cookies. Meta also states that it takes action against unauthorised scraping in its [anti-scraping guidance](https://www.facebook.com/help/463983701520800).

## Other social platforms

- Telegram's [channels and supergroups documentation](https://core.telegram.org/api/channel) describes public/private channels and notes that participant lists may be hidden. A broad network collector is not assumed.
- X documents current [pay-per-use pricing](https://docs.x.com/x-api/getting-started/pricing), [endpoint rate limits](https://docs.x.com/x-api/fundamentals/rate-limits), and follower/following endpoints in its [follows API](https://docs.x.com/x-api/users/follows/introduction). MVP does not enable paid X collection.
- LinkedIn's [access tier documentation](https://learn.microsoft.com/en-us/linkedin/marketing/increasing-access) requires product access/review for expanded marketing APIs; available scopes do not amount to arbitrary public relationship harvesting.
- TikTok's [Research Tools](https://developers.tiktok.com/products/research-api) and [Research API FAQ](https://developers.tiktok.com/doc/research-api-faq) expose research data only to eligible approved researchers and enforce quotas. Studerria's MVP use is not presumed eligible.

## Graph library choice

[Cytoscape.js](https://js.cytoscape.org/) was selected because one browser library provides interactive Canvas rendering, selectable styles/shapes, layouts and graph-oriented APIs with no runtime dependency. That is a good fit for the hard 500-node MVP cap and accessibility requirement to distinguish types by shape as well as colour.

[Sigma.js](https://www.sigmajs.org/docs/) is a strong WebGL renderer for graphs with thousands of nodes and uses Graphology as its data model. Its scale advantage is unnecessary at the current cap, while Cytoscape reduces integration surface. Re-evaluate Sigma if validated cases regularly exceed the MVP limits.

## Website collector boundary

The website collector is not a crawler or identity resolver. It accepts only HTTP(S), blocks localhost, link-local, cloud metadata and private/special-use IPv4/IPv6 destinations, resolves and pins a public address, revalidates redirects, allows standard web ports, and stops at configured page, byte and time limits. It extracts only obvious public page metadata and links. Site terms, robots preferences and applicable law remain additional operator responsibilities.
