# Carnical: API protection (`apiguard`)

Every customer who has an API gets this, with nothing to configure, and it protects better the more it knows about the API. It is one Go package, `carnical/apiguard`, with one object, `apiguard.Guard`, made once per protected site. The Guard is both an `inspect.Inspector` (it looks at each request before the rule set does and can refuse it) and an `inspect.Observer` (it is told what the application answered, and learns from the requests that went through). No state is shared between Guards.

What a proxy can do for an API, and what it cannot, is stated plainly at the end (section 9). The short version: it can refuse what does not fit the API's own description, stop a client setting a property it should not, limit abusive clients and learn the API's real shape so that what is outside it is refused. It cannot know that user 7 may not read user 8's record. That is for the application.

## 1. Putting it in

```go
guard, err := apiguard.New(apiguard.Config{})            // the zero Config is "all the defaults" (section 3)
edge, err := proxy.New(proxy.Config{
    Upstream:   origin,
    Inspectors: []inspect.Inspector{guard},               // decides
    Observers:  []inspect.Observer{guard},                // learns from what the application answered
    TrustedProxies: ...,                                  // so that inspect.Request.Client is the visitor, which the guard counts
})

// Once at start-up and then now and then (daily is plenty): find the site's own description of its API.
report, err := guard.Discover(ctx, fetch)                 // fetch is the proxy's guarded transport; the guard does no network I/O
// Save what has been learned so that a restart does not forget it, and load it back.
data, _ := guard.SaveLearned();  _ = guard.LoadLearned(data)
// The owner promotes a level when the findings in monitor have been read:
_ = guard.SetModes(apiguard.Modes{Spec: apiguard.ModeEnforce, Learned: apiguard.ModeEnforce})
```

What the owner's control plane has to do to integrate it is in section 11. `guard.Stats()` and `guard.Snapshot()` are what the console shows.

## 2. The three levels

| Level | Needs | What it does | On by default |
|---|---|---|---|
| **0, the shield** | nothing | For a request that looks like an API request: a method allow-list; a body-size cap per method; a Content-Type that must be present and be one this API uses; per-client rate limits, stricter on login-like endpoints; a warning, or a refusal where the API is known not to take it, for a write body that sets a privileged property. | yes |
| **1, the description** | an OpenAPI 3.0 / 3.1 or Swagger 2.0 document, supplied by the owner (`ImportOpenAPI`) or found by `Discover` | A model of the API's routes. A request that does not fit it is a finding: unknown route; method the route does not have (405); a path, query, header or cookie parameter of the wrong type or outside its bounds; a missing required parameter; a content type the route does not accept; a body that fails its schema; an unknown or read-only property. | looked for automatically; decides once promoted |
| **2, learning** | traffic (or a HAR file or a Postman collection) | The routes, parameters, content types and body shapes that real traffic shows, enforced once they have enough support from enough different clients (section 6). | learns from the first request |

A request is an API request if its path starts `/api`, `/v1` to `/v99`, `/rest`, `/graphql`, `/wp-json`, `/_api`, `/services`, `/odata` (or `/api-` or `/api_`); or its Content-Type is JSON, XML or newline-delimited JSON; or its `Accept` asks for one of those and does not also ask for HTML (a browser's `Accept` lists `application/xml` among the page types); or the model knows the route. Anything else is left to the rule set and to the proxy's own checks.

## 3. Modes and the defaults

`Config.Mode` caps everything: `off` (the guard does nothing), `learn` (it only learns), `monitor` (findings are reported and never block, whatever the groups below say) and `enforce` (each group acts as its own mode says; this is the default). Each protection group has its own mode:

| `Modes` field | Default | What it covers |
|---|---|---|
| `Methods` | **enforce** | a method that is not GET, HEAD, OPTIONS, POST, PUT, PATCH or DELETE (the list is `Config.Methods`) |
| `BodySize` | **enforce** | a body larger than any real request to that method (GET 16 KiB, HEAD 0, OPTIONS 4 KiB, DELETE 16 KiB, POST/PUT/PATCH 1 MiB; the proxy's own limit for bodies that are not uploads, 128 KiB, is lower and comes first) |
| `AuthRate` | **enforce** | too many attempts at an authentication endpoint: 10 in 10 seconds, 30 a minute, from one address |
| `Rate` | monitor | too many requests from one client: 40 a second, 1,200 a minute |
| `Format` | monitor | a body with no Content-Type, a Content-Type that is not a media type or that this API has not been seen to use, a body that says it is JSON and is not, a JSON object that repeats a key |
| `MassAssign` | **enforce, but** | blocks only where the description or the learned model says clients never send the property; everywhere else the finding is a warning (section 4) |
| `Spec` | monitor | level 1 |
| `Learned` | monitor | level 2 |

So a site with no configuration is protected against the clear-cut abuse from the first request, and only watched for the rest. The owner reads the findings in monitor and promotes `Spec` and `Learned` to enforce, per site, with `SetModes`. `Config.Validate()` is strict (a mode that does not exist, a limit that is negative or absurd, a burst larger than the bucket it sits in, a method that is not a method are all errors), `ParseConfig` reads a JSON configuration and refuses a field it does not know, and `New` and `SetConfig` refuse what `Validate` refuses. Durations in a JSON configuration are nanoseconds.

## 4. Level 0 in detail

**Methods and sizes.** A refused method is 405 and a body over the cap is 413, with the verdicts in the table below. The checks are the cheapest ones and come first, so a flood of requests that are refused anyway costs little.

**Content type.** A body with no `Content-Type`, or one that is not `type/subtype`, is reported. A Content-Type that has not been seen is reported only after the guard has learned which ones this site uses (a type needs the same support as anything else learned, section 6), so a new site is not told that everything is unseen.

**Rate limits.** Per client, two token buckets: a sustained one (default 1,200 a minute) and a burst one (40 a second). A request needs a token from both; a refused request takes nothing, so a client that keeps pushing is held to the rate and not made to wait longer for pushing. The refusal is status 429 and its message ends `Retry-After: N` (seconds, rounded up). The client key is the visitor's address as the proxy worked it out (an IPv6 address as its /64, the smallest block a customer is given) together with the credential presented (`Authorization`, else `X-API-Key`, else an `api_key`, `apikey` or `access_token` parameter, else one the description names), hashed with HMAC-SHA-256 under a key made at random for each Guard. The credential is never stored or logged, and nothing in the table can be tested against a guess without the key. A request with no credential is keyed by address alone. Two more counts close the ways round that:

* When a credential is presented, the **address as a whole** is counted too, at four times the limits, so changing the credential on every request does not start a new count.
* An **authentication endpoint** (a path segment that is, or starts or ends with, `login`, `signin`, `sign-in`, `token`, `oauth`, `auth`, `password`, `reset`, `forgot`, `otp`, `2fa`, `mfa`, `verify`, `register` or `signup`; `authors` and `presets` are not) has its own, much stricter limit, kept **for the address alone**: a client guessing credentials changes the credential with every try, so a limit that included it would never be reached.

Memory is bounded: the table holds at most `Rate.MaxKeys` clients (100,000 by default, about 15 MB). When it is full, a client that has been idle for as long as its buckets take to refill is forgotten (it would be handed a full bucket anyway, so nothing is lost); if there is none, the new client is let through uncounted and `Stats.RateFailOpen` goes up. The alternative choices are worse: forgetting a client who is being limited lets it start again, and refusing the new client lets anyone who can invent many addresses lock everyone else out. A request with no client address is not counted (`Stats.RateNoClient`).

**Mass assignment.** In a POST, PUT or PATCH whose body is JSON, a property named like one of these, at any depth, is found: `role`, `roles`, `is_admin`, `admin`, `is_staff`, `superuser`, `is_superuser`, `permission(s)`, `scope(s)`, `group(s)`, `verified`, `email_verified`, `balance`, `credit`, `price`, `owner`, `owner_id`, `user_id`, `tenant_id`, `org_id`, `status`, `approved`. The comparison ignores case, `_`, `-` and spaces, so `isAdmin`, `is_admin` and `IS-ADMIN` are one name. What happens next depends on what is known:

* The description or the learned model lists the property for that object: a client may set it; nothing is reported (a read-only property is a level 1 finding of its own).
* The description or the learned model describes that object's properties and this one is not among them: this API's clients do not send it. **Refused** (403, `5003021`) if `MassAssign` is enforce.
* Nothing is known about the object (no description, the route has not been learned, or the schema is free-form): a **warning** only (`5003020`), whatever the mode.

The trade-off is false positives. `price`, `status`, `owner`, `group` and `scope` are ordinary property names in plenty of write bodies (a product's price, a ticket's status), so a list of names cannot be refused outright, and it is not. It is a warning until the guard has been told, by the description or by enough traffic, that clients of this API never send it. After that, a client that starts sending it (a new release that adds a `status` field) is refused until the description is updated or `Approve`/learning in monitor teaches it (section 6). Only JSON bodies are scanned; a form post that sets `role=admin` is not.

## 5. Level 1 in detail

`ImportOpenAPI(data) (Model, Report, error)` reads OpenAPI 3.0 and 3.1 and Swagger 2.0, in JSON or YAML. The description is not trusted:

* At most 5 MiB (`MaxDocumentBytes`) and 500,000 values, counting every use of a YAML alias in full; nesting at most 64 deep. A YAML document is checked before the library sees it for the shapes that would make it slow or exhaust a stack (very deep brackets or indentation, long runs of `- - -`, more than 12,000 keys in one mapping, more values than the limit): the YAML library reads a block mapping in time that grows with the square of its keys (measured: 32,000 keys take 2.2 s and 300,000 keys in a 5 MiB document take 7 minutes 42 seconds), so without that check an origin could hold a CPU for that long.
* Only references inside the document (`#/...`) are followed, never a file or an address. A reference that is missing, that points outside, or that is a chain of more than sixteen is cut and reported, and what stands in its place accepts anything: a description the importer cannot fully read refuses less, never more. The same is true of a schema keyword this guard does not check (`if/then/else`, `patternProperties`, `dependentRequired`, `unevaluated*`, `prefixItems`, `contains`, `propertyNames`) and of a pattern that is not RE2 or is too large (at most 512 bytes and about 1,000 instructions; the subject is at most 4,096 bytes; Go's regexp package runs in time proportional to the subject).
* A schema that refers back to itself (a tree, a thread of comments) is read once and named, and is checked to whatever depth the data has. The expanded size of a description, counting each use of a reference in full, is limited to 400,000 nodes, so a description whose references fan out (A uses B twice, B uses C twice, thirty times) is refused before it is built.
* More than 5,000 routes, 64 parameters on one route, 1,000 properties in one schema or 64 alternatives in one `oneOf` is an error, not a truncation: a model with some of the routes missing would refuse real traffic.

The model holds each route (method and path template), its parameters with their schemas, the content types it accepts, the schema of a JSON body, whether a body is required or forbidden, and whether a credential is expected (the operation's `security`, else the document's; an empty requirement means anonymous). `servers` paths and `basePath` are put in front of each path. Where the description says an `apiKey` goes (a header, a query parameter or a cookie) the guard looks there too, both for the credential check and for the rate-limit key.

The validator is the guard's own, bounded: types, `required`, `properties`, `additionalProperties` (false and a schema), `items`, `enum`, `const`, `minimum`, `maximum` and their exclusive forms, `multipleOf`, `minLength`, `maxLength`, `pattern`, `minItems`, `maxItems`, `uniqueItems`, `minProperties`, `maxProperties`, `format` (`uuid`, `email`, `date`, `date-time`, `uri`, `ipv4`, `ipv6`, `hostname`, `byte`, `int32`, `int64`; an unknown format is accepted, as the specification says), `oneOf`, `anyOf`, `allOf`, `not`, `nullable` and read-only properties (a client must not send one, and a required read-only property is not required in a request). A validation does at most 400,000 steps (a value visited, an alternative tried); past that it stops and reports `5003115` rather than spending more. A value in a URL is text and is read as the type the schema asks for; a scalar parameter given twice is reported (parameter pollution).

Numbers are compared as exact decimals for integer types, enums, constants, bounds, decimal multiples and array uniqueness. Equivalent numeric spellings such as `1` and `1.0` compare equally. Bounds and `multipleOf` remain float64 fields in the SDK; import and saved-model loading refuse constraints whose shortest float64 decimal representation would change their value, rather than round them. Nonfinite bounds and nonpositive multiples are invalid. Numeric comparison and structural equality count toward the work limit; numeric exponents outside ±1,000,000,000 are refused when a numeric constraint is evaluated, and uniqueness reports a work-limit finding if a number cannot be normalized. Exponents are never expanded into allocations.

Route matching is a trie keyed by path segment. A literal is tried before a segment with a prefix or suffix (`{name}.json`), and that before a plain `{parameter}`; when a branch has no route the search backs up, so `/users/me/orders` finds `/users/{id}/orders` if `/users/me` has no `orders`. Two templates that differ only in parameter names are one route; the first is kept and the import report says so. `HEAD` is served by the `GET` route; `OPTIONS` on a known path is not held to the description (it is a preflight).

Messages name the parameter or property only where the name comes from the description (it is the owner's), never from the request.

## 6. Level 2: discovery and learning

### Discovery

`Discover(ctx, fetch)` asks, in order, for `/openapi.json`, `/openapi.yaml`, `/swagger.json`, `/swagger.yaml`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/api/openapi.json`, `/api/swagger.json`, `/swagger/v1/swagger.json`, `/docs/openapi.json`, `/.well-known/openapi.json`, `/api/v1/openapi.json` and `/wp-json/` (the WordPress REST index, whose route patterns are turned into templates, a numeric pattern becoming an integer), and notes whether `/graphql` answers. It stops at the first description that parses. The `Fetcher` is `func(ctx, path) (status, contentType, body, err)` and is the caller's, so the guard does no network I/O of its own; it only ever asks for these plain addresses, and **no GraphQL introspection query is ever sent** (it would discover the site's schema, which is not ours to do). What the site answers is treated as hostile:

* a time limit for each fetch (10 s) and for the whole discovery (60 s), a size limit (5 MiB for one document, 16 MiB for the whole discovery), a status of 200 and a content type a description can have (a single-page application answers every address with its home page as `text/html`, which is refused), and a look at the first lines before anything is parsed;
* then the import of section 5, which is where a hostile document is stopped: oversized, nested very deep, a YAML alias bomb, a `$ref` loop or fan-out, a mapping with hundreds of thousands of keys.
* A panic in the fetcher is an error, not a crash; the report never repeats what the fetcher said.

The result is kept as a **candidate**: it records where it came from and when, and **it refuses nothing**. Each request that is answered below 400 is held against it, and when at least 20 of them (`Discovery.AgreeMinimum`), under the same several-clients rule as everything learned, fit it and no more than 1 in 20 does not, it is promoted to active. A description that disagrees with real traffic is never promoted, so it never starts refusing real clients. `Promote()` does it by hand, and `Discovery.ManualPromotion` turns the automatic rule off. `Refresh(ctx, fetch, force)` runs discovery again; what it finds replaces the held description only if it is not worse (not fewer routes) unless forced, and it replaces it as a candidate, so the description in force stays in force until the new one has been shown to fit.

### What is learned

For each request answered with a status of 200 to 399 (and not a refused one: the proxy does not tell the observer about those), if it is an API request, the guard records:

* **The route.** The path is made into a template by the segment's look: all digits (up to 19) is `{int}`; 8-4-4-4-12 hex is `{uuid}`; `YYYY-MM-DD` (and a date-time) is `{date}`; 8 or more hex characters with a digit is `{hex}`; 20 or more base64-ish characters with upper and lower case is `{token}`; a word with a digit that is not a version (`v1`, `v2.1`) or a known word (`oauth2`, `2fa`, `ipv6`) is `{id}`; anything else is a literal. A literal that is too long, has a space or a brace in it, becomes `{id}`. A path position that holds many different words, each seen only once or twice, becomes a parameter too: more than 8 different words (`Learn.DistinctValues`), at least 50 sightings, and fewer than half of the words seen three times. The last two conditions are a refinement of "more than 8 different words": without them an API with fifteen resources (`/api/users`, `/api/orders`, ...) would be read as `/api/{id}`, since each resource name is a different word. A collapse drops what was learned under the separate words, which are learned again under the parameter.
* **The method.** `HEAD` is learned as `GET`; `OPTIONS` is not learned at all (an application answers it for any path).
* **Query parameters:** their names, the kinds of value they take (integer, number, boolean, uuid, date, string, and empty, which is always allowed), and, for a parameter whose values are words and take at most 8 different ones with at least two believed, the values (an enumeration). The range of integers and the longest length are recorded in the model for the owner to read and are **not enforced**: one client can widen a range.
* **The content types** of the bodies, per route and for the whole site.
* **The shape of JSON bodies,** to a depth of 8, 64 properties per object and 16 items per array: for every property its name, the JSON types seen and whether it is **required** (present in at least 95% of at least 20 objects).

### The evidence rule: how an attacker is kept from teaching the guard that an attack is normal

A route, a parameter, a kind of value, a property or a value becomes **enforceable** only when it has been seen at least **30** times (`Learn.MinObservations`), from at least **3** different clients (`MinClients`), with no one client accounting for more than **20%** of the sightings (`MaxClientShare`). Until then it is *being learned*: it is recorded and refuses nothing, and it does not count as known. The rule is kept for each thing separately, so one client cannot add a property or a parameter to a route that the crowd has made enforceable.

* "A client" is the visitor's address cut to its /24 (IPv4) or /48 (IPv6), kept as an identifier made with a key that belongs to the Guard. A person with a block of addresses is one client.
* The evidence is kept in a fixed space (16 clients' counts per thing) by the Space-Saving method: when it is full, a new client takes the place of the one with the fewest sightings and inherits its count. The counts are never below the truth, so the share that is computed is never below the truth either; every error makes the guard slower to trust, never quicker. This is tested.
* Once enough, always enough: the evidence does not take itself back if one client later dominates.
* **What it takes to teach the guard something false:** at least five clients (at 20% each), all getting an answer below 400 from the application, and 30 sightings between them. One address, or two, or four sharing it equally, cannot do it however often it asks; this is the first test of the learner, run against a flood of 5,000 requests per kind, with a control that shows five clients can.
* The other face of the rule: a client that floods a legitimate route before the crowd has used it keeps that route from becoming enforceable until the crowd has used it about four times as much as the flooder. That delays learning; it never teaches.
* A recording supplied by the owner (`ImportHAR`, `ImportPostman`, `Approve`) is the owner's word and counts as full evidence at once. Pages and scripts in a HAR are left out (a call that was answered with JSON or XML, or has an API path, is an API call), the credentials in a request (`Authorization`, `Cookie`) are not kept, and the limits are 64 MiB and 20,000 entries for a HAR (it holds every response body the browser loaded, so it is larger than a description) and 5 MiB for a Postman collection.

### What it does with what it learned

A route that is enforceable is checked: each parameter with an enforceable kind of value, the enumerations, the properties, their types, which are required, the content types, whether a body is expected. A request that matches **no enforceable route** is an unknown route (`5003200`) or a known path with an unseen method (`5003201`), once the guard has at least one enforceable route and when no description is in force (the description, where there is one, decides). A route in the middle of being learned is not known.

**A new endpoint or a new field is refused while `Learned` is enforce, and a refused request is never seen by the learner, so it cannot teach itself.** The owner has two ways to teach: `Approve(method, path)` for a route, and putting `Learned` back to monitor or learn for a while for parameters and properties, then enforce again. Move `Learned` to enforce only after the findings in monitor have been read, and again after a release that adds endpoints.

Memory is bounded: at most 2,000 learned routes, 4,096 path positions, 200,000 records of parameters and body shape in all (`Learn.MaxRoutes`, `MaxPositions`, `MaxNodes`); 32 parameters and 8 content types on a route. When a limit is reached the thing is not learned and `Stats.LearnDropped` goes up. A route that never became enforceable is forgotten after 7 days unseen and one that did after 30 (`LearningTTL`, `RouteTTL`), a route in use never. `Snapshot()` returns the model with each route's state, `declared`, `candidate`, `learned-enforceable` or `learning`, and `SaveLearned`/`LoadLearned` (and `Model.MarshalJSON`/`UnmarshalJSON`) save and load it in a versioned format (`"format": 1`), read strictly: an unknown field, another version, a document over 32 MiB, more routes than the limit, a schema nested too deeply or evidence for too many clients is refused and nothing changes.

## 7. The verdicts

Identifiers 5003000 to 5003999; the proxy's own refusals use 5000000 to 5000999. Each is reported with a fixed message that never holds anything the visitor sent. A refusal has the status shown (the proxy answers with it); a finding in monitor is logged and the request goes on. `apiguard.Verdicts()` returns this table and a test checks this document against it.

**Level 0: the shield**

| ID | Name | Mode field | Status | Severity | What it means |
|---|---|---|---|---|---|
| 5003001 | method not allowed | Methods | 405 | medium | The method is not on the allow-list. |
| 5003002 | body too large | BodySize | 413 | medium | The body is larger than any request to that method should carry. |
| 5003003 | content type missing | Format | 415 | low | The request has a body and no Content-Type. |
| 5003004 | content type unseen | Format | 415 | low | The Content-Type is not one this API has been seen to use, or is not a media type. |
| 5003005 | body malformed | Format | 400 | low | The body says it is JSON and is not valid JSON. |
| 5003006 | body repeats a key | Format | 400 | medium | A JSON object repeats a key, which different parsers read differently. |
| 5003010 | rate limited | Rate | 429 | medium | One client sent more requests than the sustained or burst limit. |
| 5003011 | authentication rate limited | AuthRate | 429 | high | Too many requests to an authentication endpoint from one address (credential stuffing, password guessing). |
| 5003020 | mass assignment suspected | MassAssign | 403 | medium | A write body sets a privileged property (role, admin, price and the like). A warning only: nothing says clients never send it. |
| 5003021 | mass assignment | MassAssign | 403 | high | A write body sets a privileged property that the description or the learned model says this API's clients never send. |
| 5003990 | internal error | - | - | high | The guard failed on this request and did not inspect it. Never blocks. |

**Level 1: the API's own description**

| ID | Name | Mode field | Status | Severity | What it means |
|---|---|---|---|---|---|
| 5003100 | unknown route | Spec | 404 | medium | No route in the description matches the path. |
| 5003101 | method not allowed on route | Spec | 405 | medium | The path is in the description but not with this method. |
| 5003102 | path parameter invalid | Spec | 400 | medium | A path parameter has the wrong type or is outside its bounds. |
| 5003103 | query parameter invalid | Spec | 400 | medium | A query parameter has the wrong type, is outside its bounds, or is given more than once. |
| 5003104 | header parameter invalid | Spec | 400 | low | A header parameter has the wrong type or is outside its bounds. |
| 5003105 | cookie parameter invalid | Spec | 400 | low | A cookie parameter has the wrong type or is outside its bounds. |
| 5003106 | required parameter missing | Spec | 400 | medium | A parameter the description requires is not there. |
| 5003107 | content type not accepted | Spec | 415 | medium | The route does not accept this Content-Type. |
| 5003108 | body does not match schema | Spec | 400 | medium | The JSON body does not satisfy the route's schema. |
| 5003109 | unknown property | Spec | 400 | medium | The body has a property the schema does not allow. |
| 5003110 | read-only property | Spec | 403 | high | The body sets a property the schema marks read-only. |
| 5003111 | body missing | Spec | 400 | low | The route requires a body and there is none. |
| 5003112 | unexpected body | Spec | 400 | low | The route takes no body and the request has one. |
| 5003113 | unknown query parameter | Spec | 400 | low | A query parameter the route does not list (only with RefuseUnknownParams). |
| 5003114 | credential missing | Spec | 401 | low | The route requires a credential and none was presented. |
| 5003115 | too complex to check | Spec | 400 | medium | The body needs more work to check than the guard allows. |

**Level 2: what was learned**

| ID | Name | Mode field | Status | Severity | What it means |
|---|---|---|---|---|---|
| 5003200 | route never seen | Learned | 404 | low | No learned route matches the path. |
| 5003201 | method never seen on route | Learned | 405 | low | The path is a learned route but this method has not been seen on it. |
| 5003203 | query parameter unlike what was seen | Learned | 400 | medium | A query parameter has a kind of value, or a value, that was never seen for it. |
| 5003204 | query parameter never seen | Learned | 400 | low | A query parameter that was never seen on the route. |
| 5003205 | query parameter missing | Learned | 400 | low | A parameter that every request to the route carried is missing. |
| 5003206 | content type never seen on route | Learned | 415 | low | The Content-Type was never seen on the route. |
| 5003207 | body value of an unseen type | Learned | 400 | medium | A body property has a JSON type it was never seen with. |
| 5003208 | body property never seen | Learned | 400 | low | The body has a property that was never seen on the route. |
| 5003209 | body property missing | Learned | 400 | low | A property that every body on the route carried is missing. |
| 5003210 | body never seen on route | Learned | 400 | low | The route has never been seen with a body. |
| 5003211 | body missing on route | Learned | 400 | low | Every request to the route carried a body and this one does not. |

Order of checks: method, size, rate limits, content type and JSON syntax, **mass assignment**, the description, what was learned. Evaluation stops at the first finding that blocks (the cheap refusals therefore cost least, and a refusal of a privileged property is reported before the more general "unknown property"); findings that do not block are all reported, up to 16.

## 8. Failures and limits of the guard itself

* A failure inside the guard (a panic, which the tests and the fuzzing did not find) is reported as `5003990`, which does not block, and counted in `Stats.Panics`; the request goes on to the rule set. `Observe` never blocks and never panics.
* The guard is safe for many requests at once. The rate table is split into 64 locks; the learned routes have a lock each, and the table of routes is locked for writing only when a route appears or goes; what a request is checked against is an immutable view swapped in whole. Tests run with `-race`.
* Nothing from a request is put in a verdict, a log line or an error. A test sends canary strings in every place a request has and looks for them in every message.
* The rate table's size is fixed when the Guard is made; `SetConfig` changes everything else on the next request.

## 9. What no WAF can do

State this plainly to customers.

* **Broken object-level authorisation (BOLA, IDOR).** `GET /orders/1234` and `GET /orders/1235` are both well formed, both match the description, both have an integer in the path, and a WAF cannot know that the person asking owns the first and not the second. Only the application knows. The same goes for **broken function-level authorisation** (an ordinary user calling an admin route that is in the description) and for anything that needs to know who the user is and what they may do.
* **Business logic.** A discount applied twice, a refund larger than the payment, a coupon used from two addresses at once, a race between two requests (single-packet attacks). The request is valid; the sequence is the attack.
* **Mass assignment in general.** The guard finds the privileged property names it lists and the properties a description or learning says a client does not send. A property it has never heard of that the application binds blindly (`is_premium`) is invisible until a description or learning says clients do not send it. Fix it in the application: bind only the fields a client may set.
* **A stolen credential used by someone who is allowed to use it,** JWT and OAuth flaws, GraphQL batching, aliasing and depth (the guard notes that GraphQL is present, and never reads its schema).
* **Slow abuse.** A client that stays under the limits, or that spreads itself over many addresses, is not limited. The limits stop the loud ones.

## 10. What was verified, and how

Publication checks on 2026-10-06 used Windows and Go 1.26.6. Normal and race package tests pass, including local proxy
requests, schema enforcement, discovery, learning and bounded rate state. The harness is `go test ./apiguard/`.
The standalone executable's 500,000-request run exercises CRS and format enforcement; it does not automatically install
this API guard. Package-level validation and standalone load measurements cover different integration boundaries.

The executable now optionally installs explicit local OpenAPI contracts with `-api-spec` and `-api-spec-mode`.
See [input hardening](input-hardening.md) for its supported enforcement subset and live checks. Without that flag,
the standalone binary still runs no API description or learning model.

## 11. What the owner has to do to integrate it

1. Make one `apiguard.Guard` per protected site (`apiguard.New(cfg)`), keep it with the site's proxy and give the proxy the same object as an inspector and as an observer. The Guard keeps all of a site's state; never share one between sites.
2. Give `Discover` a `Fetcher` that uses the proxy's guarded transport (the one that refuses private addresses at the moment of connection), with a read limit of `apiguard.MaxDocumentBytes+1`. Run `Refresh` daily. Show `Report` and `Snapshot()` in the console; a candidate is waiting for a promotion if `Stats().ModelState` is `candidate`.
3. Save `SaveLearned()` to the site's own store now and then (every few minutes is enough; it is a few hundred KB for a large API) and `LoadLearned` it on start. The model is per site and holds identifiers made with a key that belongs to the Guard, so do not load one site's model into another.
4. Give the console three buttons that call `SetModes`: promote `Spec` to enforce, promote `Learned` to enforce, and back to monitor. Show `Stats().ByVerdict` next to them: the owner should enforce a level only after reading what it reports in monitor.
5. Wire the new-endpoint path: when the site's owner ships a route, `Approve(method, path)`, or put `Learned` to monitor for a while.
6. Put `Stats()` on the feed; `RateFailOpen` and `LearnDropped` above zero are worth an alert.
7. Do not give `Config.Clock` outside tests.
