
import sys
import socket
import random
import signal
import ssl
import concurrent.futures
import ipaddress
import urllib.request
import urllib.error

WORDLIST = [
    "www","web","web1","web2","web3","web4","web5","www1","www2","www3",
    "app","app1","app2","app3","apps","application","applications",
    "portal","portals","gateway","gw","gw1","gw2",
    "api","api1","api2","api3","api4","api5","apis","api-gateway",
    "rest","graphql","soap","rpc","grpc","ws","wss","websocket",
    "v1","v2","v3","v4","v5","v1api","v2api","v3api",
    "mobile","m","m2","wap","pda","tablet","touch",
    "mobi","responsive","app-mobile","mapp",
    "mail","mail1","mail2","mail3","webmail","mta","mda","mua",
    "smtp","smtp1","smtp2","smtps","relay","relay1","relay2",
    "pop","pop3","imap","imap1","imap2","imap3",
    "exchange","owa","outlook","autodiscover","autoconfig",
    "mx","mx1","mx2","mx3","mxpool","mailhost",
    "spam","antispam","filter","filtering","quarantine",
    "list","lists","maillist","newsletter","bulk","bounce",
    "ses","sendgrid","mailgun","postmark","mandrill",
    "ns","ns1","ns2","ns3","ns4","ns5","ns6","nameserver","dns","dns1","dns2",
    "pdns","coredns","bind","nsd","knot","resolver",
    "cdn","cdn1","cdn2","cdn3","edge","edge1","edge2","static","statics",
    "assets","asset","img","images","image","pics","pictures","photo",
    "media","media1","media2","video","videos","stream","streaming",
    "audio","files","file","upload","uploads","download","downloads",
    "content","contents","resources","resource","fonts","css","js",
    "auth","auth1","auth2","login","logout","sso","idp","sp",
    "oauth","oidc","openid","saml","adfs","federation","trust",
    "id","identity","accounts","account","signup","register",
    "user","users","member","members","profile","profiles",
    "password","passwd","reset","forgot","recover","recovery",
    "verify","confirm","activate","mfa","2fa","otp","totp",
    "okta","ping","duo","shibboleth","cas","keycloak",
    "admin","admin1","admin2","administrator","root","superadmin",
    "manage","manager","management","console","dashboard",
    "panel","cpanel","whm","plesk","directadmin","webdisk",
    "control","controlpanel","backend","backoffice","staff",
    "helpdesk","servicedesk","ticket","tickets","support",
    "vpn","vpn1","vpn2","vpn3","openvpn","wireguard","ipsec",
    "remote","remote1","remote2","rdp","citrix","bastion",
    "ssh","telnet","jump","jumpbox","proxy","proxy1","proxy2",
    "waf","firewall","fw","ids","ips","dlp","nac","sandbox2",
    "lb","load","balancer","ha","cluster","cluster1","cluster2",
    "router","switch","mgmt","mgmt1","pdu","ipmi","idrac","ilo",
    "dc","dc1","dc2","hq","office","corp","intranet","internal",
    "extranet","partner","partners","vendor","vendors","b2b",
    "cloud","aws","azure","gcp","k8s","kubernetes","docker",
    "registry","registry1","harbor","nexus","artifactory",
    "helm","operator","node","node1","node2","worker","workers",
    "serverless","lambda","function","faas","paas","iaas","saas",
    "container","containers","pod","pods","svc","service","ingress",
    "git","gitlab","github2","bitbucket","gitea","gogs","svn","cvs",
    "jenkins","ci","cd","pipeline","pipelines","build","builds",
    "artifact","artifacts","release","releases","deploy","deployment",
    "sonar","sonarqube","codecov","codecoverage","quality","qa","qat",
    "terraform","ansible","puppet","chef","salt","capistrano",
    "jira","confluence","wiki","wiki2","kb","knowledgebase","docs",
    "docs2","manual","guide","tutorials","runbook","playbook",
    "monitor","monitor1","monitoring","status","health","healthcheck",
    "ping","uptime","pingdom","grafana","grafana2","kibana","elastic",
    "elasticsearch","logstash","fluentd","loki","tempo","cortex",
    "thanos","victoria","mimir","influx","influxdb","telegraf",
    "prometheus","alertmanager","pagerduty","opsgenie","statuspage",
    "nagios","zabbix","icinga","prtg","mrtg","cacti","netdata",
    "datadog","newrelic","dynatrace","appdynamics","instana",
    "sentry","bugsnag","rollbar","honeybadger","airbrake","raygun",
    "logrocket","fullstory","hotjar","mouseflow","clarity","heap",
    "db","db1","db2","db3","database","sql","mysql","postgres","oracle",
    "mongo","mongodb","redis","redis1","elasticsearch2","cassandra",
    "couchdb","rethinkdb","neo4j","influxdb2","timescale","cockroach",
    "tidb","vitess","galera","percona","mariadb","mssql","sqlserver",
    "rds","aurora","atlas","aiven","planetscale",
    "s3","blob","bucket","object","storage","storage1","store",
    "nas","san","nfs","smb","afp","ftp","ftp2","sftp","scp",
    "backup","backup1","backup2","backups","archive","archives",
    "dr","disaster","recovery2","failover","standby","replica",
    "restic","borg","veeam","cohesity","rubrik","bacula",
    "mq","rabbitmq","kafka","nats","activemq","redis2","sidekiq",
    "celery","resque","queue","queues","broker","broker1","topic",
    "pub","pubsub","eventhub","sqs","sns","kinesis","servicebus",
    "push","notify","notification","notifications","sms","whatsapp",
    "telegram","slack","discord","teams","zoom","meet","webex",
    "prod","production","pre","preprod","pre-prod","staging","staging1",
    "staging2","stage","stage1","stage2","dev","dev1","dev2","dev3",
    "development","test","test1","test2","test3","testing","uat",
    "qa","qa1","qa2","sandbox","sandbox1","lab","labs","research",
    "alpha","beta","preview","demo","demo1","demo2","poc","canary",
    "blue","green","dark","experiment","ab","perf","performance",
    "load","stress","capacity","nightly","release-candidate","rc",
    "flags","toggles","config","config1","config2","settings","env",
    "launchdarkly","optimizely","growthbook","flipt","unleash","flagsmith",
    "posthog","split","segment","mixpanel","amplitude","rudderstack",
    "analytics","analytics2","stats","statistics","tracking","track",
    "pixel","beacon","survey","forms","form","report","reports",
    "ga","gtm","matomo","piwik","snowplow","heap2","plausible",
    "shop","shop1","store2","market","marketplace","checkout","cart",
    "order","orders","catalog","product","products","payment","payments",
    "billing","billing1","invoice","invoices","stripe","paypal","braintree",
    "subscription","subscriptions","license","licenses",
    "blog","news","press","media3","magazine","journal","feeds","rss",
    "cms","wordpress","drupal","joomla","ghost","contentful","prismic",
    "sanity","strapi","directus","wagtail","typo3","umbraco",
    "hr","erp","crm","sap","salesforce","hubspot","zoho","freshdesk",
    "zendesk","intercom","servicenow","workday","bamboo","bamboohr",
    "greenhouse","lever","taleo","successfactors","netsuite",
    "siem","soar","xdr","edr","crowdstrike","cylance","carbon","cb",
    "sentinel","wazuh","ossec","falco","vault","vault1","kms","hsm",
    "pki","ca","ocsp","crl","ldap","ad","active","directory",
    "radius","tacacs","kerberos","scan","scans","pentest","bugbounty",
    "secure","ssl","tls","certs","certs1","cert","certificate",
    "waf2","proxy3","sandbox3","deception","honeypot",
    "go","goto","link","links","redirect","short","shortlink","url",
    "click","r","r2","r3","redir","track2","open","public",
    "1","2","3","4","5","6","7","8","9","10",
    "us","eu","uk","de","fr","ap","sg","au","ca","br","in","jp","cn",
    "us-east","us-west","eu-west","ap-southeast","ap-northeast",
    "east","west","north","south","central",
    "a","b","c","d","e","f","g","h","i","j","k","l","n","o","p","q",
    "t","u","v","x","y","z",
    "new","old","legacy","migrate","migration","temp","tmp","bak",
    "disabled","inactive","decommissioned","deprecated","retired",
    "spare","reserve","overflow","replica2","slave","master","leader",
    "primary","secondary","tertiary","active","passive",
    "api-dev","api-test","api-staging","api-prod","api-v2","api-v3",
    "app-dev","app-test","app-staging","app-prod",
    "web-dev","web-test","web-staging","web-prod",
    "db-dev","db-test","db-staging","db-prod",
    "mail-dev","mail-test","mail-staging",
    "vpn-dev","vpn-test","vpn-staging",
    "auth-dev","auth-test","auth-staging","auth-prod",
    "admin-dev","admin-test","admin-staging",
    "cdn-dev","cdn-test","cdn-staging",
    "monitor-dev","monitor-test",
    "ci-dev","ci-test","ci-staging",
    "infra","infra1","infra2","infra3","platform","platforms",
    "data","data1","data2","data3","lake","warehouse","mart",
    "lake1","datalake","datawarehouse","datamart","bigdata",
    "spark","flink","beam","airflow","prefect","dagster","luigi",
    "etl","elt","dbt","nifi","kafka3","kinesis2","pubsub2",
    "redshift","bigquery","snowflake","databricks","synapse","athena",
    "glue","emr","hdfs","hive","presto","trino","doris","druid",
    "superset","metabase","looker","tableau","powerbi","qlik",
    "jupyter","notebook","notebooks","colab","mlflow","kubeflow",
    "ray","dask","rapids","feast","tecton","sagemaker","vertex",
    "train","training2","inference","serving","predict","models",
    "ai","ml","nlp","cv","ocr","tts","stt","llm","gpt","embedding",
    "vector","vectordb","qdrant","weaviate","milvus","pinecone",
    "langchain","llamaindex","openai","anthropic","cohere","mistral",
    "devops","devsecops","sre","platform2","tooling","tools",
    "repo","repos","packages","package","pypi","npm","maven","gradle",
    "composer","nuget","rubygems","crates","pkg","packages2",
    "apk","ios","android","react","vue","angular","next","nuxt","svelte",
    "spa","ssr","ssg","pwa","cordova","ionic","expo","reactnative",
    "electron","tauri","nwjs","flutter","dart","kotlin","swift",
    "unity","unreal","godot","games","game","gaming","esports",
    "tokens","token2","nft","web3","blockchain","crypto","defi","dao",
    "ipfs","ens","wallet","wallets","node3","rpc2","jsonrpc","ws2",
    "kafka4","zookeeper","etcd","consul","nomad","terraform2",
    "atlantis","spacelift","env0","scalr","pulumi","cdk","sst",
    "crossplane","argocd","fluxcd","tekton","spinnaker","harness",
    "codefresh","circleci","travisci","drone","woodpecker","buildkite",
    "gitops","helm2","helmfile","kustomize","skaffold","tilt","garden",
    "backstage","pagerduty2","incidents","incident","post-mortem",
    "sla","slo","sli","oncall","on-call","rotation","escalation",
    "blameless","firehydrant","rootly","allquiet","opslevel",
    "port","cortex2","compass","service-catalog","apicurio","stoplight",
    "swagger","openapi","asyncapi","protobuf","thrift","avro2",
    "schema","schemas","registry2","apigee","kong","traefik","envoy",
    "istio","linkerd","consul2","dapr","knative","kserve",
    "rancher","openshift","tanzu","aks","eks","gke","ecs","fargate",
    "containerd","podman","buildah","kaniko","trivy","snyk","aqua",
    "twistlock","lacework","orca","prisma","checkov","tfsec",
    "cloudtrail","cloudwatch","stackdriver","cloudlogging","loganalytics",
    "eventbridge","stepfunctions","sfn","workflow2","temporal","cadence",
    "zeebe","camunda","activiti","flowable","n8n","zapier","make",
    "integromat","automate","power-automate","apify","playwright",
    "selenium","cypress","puppeteer","testcafe","webdriverio",
    "k6","locust","gatling","jmeter","artillery","wrk","hey","vegeta",
    "chaos2","chaosmonkey","litmus","gremlin","steadybit","reliably",
    "featureflags","unleash2","posthog2","statsig","eppo","absmartly",
    "launchdarkly2","cloudflare","fastly","akamai","cloudfront",
    "imperva","sucuri","bunny","keycdn","stackpath","leaseweb",
    "hetzner","ovh","linode","digitalocean","vultr","exoscale",
    "scaleway","upcloud","civo","fly","railway","render","heroku",
    "netlify","vercel","pages","workers","r2","kv2","d1","turnstile",
    "neon","planetscale2","supabase","turso","upstash","convex","xata",
    "pocketbase","appwrite","firebase","firestore","realtimedb",
    "dynamodb","cosmosdb","faunadb","arangodb","dolt","eventsdb",
    "timescaledb","questdb","clickhouse","scylladb","yugabyte","cockroach2",
    "firebolt","motherduck","duckdb","sqlite","spatialite","postgis",
    "opensearch","typesense","meilisearch","algolia","manticore","sphinx",
    "hazelcast","ignite","gridgain","coherence","ehcache","caffeine",
    "memcached","dragonflydb","keydb","valkey","garnet","kvrocks",
    "geode","gemfire","tarantool","aerospike","couchbase","riak",
    "voldemort","dynamo","bbolt","badger","leveldb","rocksdb","pebble",
    "wiredtiger","lmdb","mdbx","forestdb","nuodb","memsql","singlestore",
    "exasol","vertica","greenplum","hawq","hana","teradata","netezza",
    "informix","db2","sybase","ingres","pervasive","progress","openedge",
    "filemaker","access","foxpro","clipper","dbase","paradox","borland",
    "about","about-us","abuse","action","activate","address","adm","admin3",
    "administration","administrative","ads2","adserver","adservices","adsl",
    "adtech","adtracking","advertising","affiliates","agent","agents",
    "agile","agreement","ai2","alerts","alias","all","alliance","amp",
    "announce","announcement","anywhere","api-docs","api-internal","api-public",
    "api-sandbox","api-secure","api-test","app-api","app-internal","app-server",
    "application2","appointments","archive2","arm","art","article","articles",
    "assessment","asset2","assignments","assist","assistance","associate",
    "association","async2","attach","attachment","attachments","attest",
    "auction","auctions","audit","auditor","aurora","author","authors",
    "authority","auto","autotest","aux","award","awards",
    "baas2","back","backend2","backoffice2","bank","banner","banners",
    "base","bastion2","batch2","benefits","beta2","board","boards",
    "bookings","bot","bots","box","bridge","broadcast","business",
    "cafe","campaign","campaigns","capacity2","capture","career",
    "catering","central","chain","challenge","channels","charge",
    "check","checker","checkout2","city","claim","claims","classes",
    "clean","cleaner","clearance","client2","close","code","codes",
    "collect","collection","collections","collector","column","command",
    "commerce","commit","common","community2","compare","compile",
    "complete","compliance","compute","connect2","connection","contract",
    "contractor","contribute","controller","conversion","convert","coordinator",
    "core","corner","corp2","counter","coupon","coupons","crawler",
    "creative","crew","cross","crypto2","custom","customer2","cv",
    "deal","deals","debug","default","delivery","demo3","designer",
    "details","detect","developer","developers","development2","devtest",
    "devtools","direct","directory2","discovery","discussion","distribute",
    "distribution","domain2","downloadcenter","drive","driver","dump",
    "dynamic","earnings","editor","education","employee","employees",
    "endpoint","engine","engineer","engineering","enterprise","entry",
    "environment2","error","errors","eval","event2","everyone","exam",
    "exchange2","execute","existing","experiments","export2","express",
    "external","external2","factory","fail","failback","failure","faq2",
    "feedback","finance","financial","fix","flow","flows","focus",
    "footer","fox","framework","free","front","frontend","functions2",
    "fusion","gatekeeper","geo2","get","ghost2","global","global2",
    "government","group","groups","grow","handler","handlers","header",
    "history","home","homepage","host","hosting","hosts","hub","human",
    "id2","image2","imageserver","imaging","import2","inbox","index2",
    "industrial","industry","info","information","inputs","instance",
    "int","integration2","interface","intro","inventory","investor",
    "investors","ip","issue","issues","job","journal","jump2","kiosk",
    "knowledge","known","language","large","launch2","layer","layout",
    "lead","leads","learning","legacy2","liferay","light","live2","local2",
    "location2","log","logger","logging","logic","lookup","loopback",
    "machine","maintenance","marketplace2","master2","media4","meeting",
    "merchant","merge","message","messages","messaging","metric","mirror",
    "mixed","model2","money","monthly","motion","mount","my","myaccount",
    "myapp","myportal","network","new2","news2","next2","none","noreply",
    "not","objects","offers","offline","onboard","one","online","open2",
    "optimize","orchestration2","origin","page","payment2","payroll",
    "peer","people","performance2","phone","place","platform3","player",
    "plugin","plugins","policy","pool","portfolio","post","posts",
    "prepare","premium","price","pricing","print","priority","probe2",
    "process","processor2","product2","production2","projects","property",
    "proposal","prototype","provider","public2","publish","publisher2",
    "push2","put","query","queue2","real","records","relay3","reports2",
    "reseller","restriction","retail","rights","route","rules","run",
    "runner","sale","sales","scanner","schema2","screen","secret2",
    "security2","send","sender","server","server2","server3","service2",
    "session2","shop2","show","signal","simple","site","sites","smart",
    "software","solution","solutions","source","space","speed","spider",
    "stable","start","started","state","states","submit","subscribe",
    "success","summary","system","systems","table","task","tasks",
    "team","test4","testing2","theme","threats","transaction","transactions",
    "transfer","transit","trial","trusted","tunnel","type","update",
    "updates","user2","users2","util","utils","utilities","validation",
    "value","version","view","views","voice","volunteer","warning",
    "website","weekly","welcome","widget","widgets","work","workspace",
    "writer","xml","xmpp2","yearly","zone",
    "mail4","mail5","smtp3","smtp4","ftp3","sftp2","vpn4","vpn5",
    "web6","web7","web8","web9","web10","app4","app5","app6","app7",
    "api6","api7","api8","api9","api10","ns7","ns8","ns9","ns10",
    "db4","db5","db6","db7","db8","cdn4","cdn5",
    "node3","node4","node5","node6","node7","node8","node9","node10",
    "worker3","worker4","worker5","dev4","dev5","dev6",
    "stage3","stage4","stage5","test5","test6","test7",
    "prod2","prod3","prod4","prod5","monitor3","monitor4",
    "lb2","lb3","lb4","proxy4","proxy5","relay4","relay5",
    "backup3","backup4","backup5","replica3","replica4",
]

_seen_w = set()
_deduped  = []
for _w in WORDLIST:
    if _w not in _seen_w:
        _seen_w.add(_w)
        _deduped.append(_w)
WORDLIST = _deduped

_shutdown = False
def _handle_sig(s, f):
    global _shutdown
    _shutdown = True
signal.signal(signal.SIGINT,  _handle_sig)
signal.signal(signal.SIGTERM, _handle_sig)

RESOLVERS = [
    "8.8.8.8",   "8.8.4.4",
    "1.1.1.1",   "1.0.0.1",
    "9.9.9.9",   "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    "64.6.64.6", "64.6.65.6",
    "94.140.14.14", "94.140.15.15",
    "76.76.2.0",  "76.76.10.0",
]


def resolve(subdomain: str) -> str | None:
    if _shutdown:
        return None
    subdomain = subdomain.strip()
    if not subdomain:
        return None
    resolver = random.choice(RESOLVERS)
    try:
        import dns.resolver
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [resolver]
        r.timeout = 3
        r.lifetime = 5
        answers = r.resolve(subdomain, "A")
        public = [str(a) for a in answers
                  if not ipaddress.ip_address(str(a)).is_private]
        if not public and len(answers) > 0:
            return None
        return subdomain
    except Exception:
        pass
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(subdomain)
        return subdomain
    except Exception:
        return None


def wildcard_check_dns(domain: str) -> set:
    wildcard_ips: set = set()
    for prefix in ["g4rxd-nowildcard-xzqy", "zzz-brute-test-g4rxd", "noexist-g4rxd-abc"]:
        test = f"{prefix}.{domain}"
        try:
            import dns.resolver
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = RESOLVERS[:4]
            r.timeout = 3
            r.lifetime = 5
            ans = r.resolve(test, "A")
            for a in ans:
                wildcard_ips.add(str(a))
        except Exception:
            try:
                infos = socket.getaddrinfo(test, None)
                for item in infos:
                    wildcard_ips.add(item[4][0])
            except Exception:
                pass
    return wildcard_ips


def _http_fetch(ip: str, port: int, scheme: str,
                host_header: str, timeout: int = 10):
    if _shutdown:
        return None
    url = f"{scheme}://{ip}:{port}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode   = ssl.CERT_NONE
    headers = {
        "Host":            host_header,
        "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 g4rxd-vhost/3.1",
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection":      "close",
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        kw  = {"timeout": timeout}
        if scheme == "https":
            kw["context"] = ctx
        with urllib.request.urlopen(req, **kw) as r:
            body = r.read(8192).decode("utf-8", errors="ignore")
            return r.getcode(), len(body), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, len(body), body
    except Exception:
        return None


def _vhost_baseline(ip: str, port: int, scheme: str, domain: str, timeout: int = 10):
    rand_sub = f"zz-nowildcard-{random.randint(10000,99999)}.{domain}"
    base = _http_fetch(ip, port, scheme, domain, timeout)
    wild = _http_fetch(ip, port, scheme, rand_sub, timeout)
    if base is None:
        return None, None, None
    base_code, base_len, _ = base
    wild_len = wild[1] if wild else None
    return base_code, base_len, wild_len


def _probe_vhost(ip: str, port: int, scheme: str, domain: str, word: str,
                 base_code: int, base_len: int, wild_len,
                 filter_size: int, size_delta: int,
                 filter_codes: set, match_codes,
                 timeout: int = 10):
    if _shutdown:
        return None
    fqdn   = f"{word}.{domain}"
    result = _http_fetch(ip, port, scheme, fqdn, timeout)
    if result is None:
        return None
    code, length, _ = result

    if match_codes and code not in match_codes:
        return None
    if filter_codes and code in filter_codes:
        return None

    if filter_size is not None and abs(length - base_len) <= filter_size:
        return None

    if wild_len is not None and abs(length - wild_len) <= size_delta:
        return None

    if code == base_code and abs(length - base_len) <= size_delta:
        return None

    return fqdn, code, length


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="brute.py",
        description="DNS brute-forcer + VHost scanner (g4rxd v3.1.0)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard DNS brute-force (real domains)
  python3 brute.py example.com 100

  # VHost mode — for HTB / .htb / .thm / .local targets
  python3 brute.py pterodactyl.htb 100 --vhost 10.129.1.46
  python3 brute.py pterodactyl.htb 100 --vhost 10.129.1.46 --vhost-port 8080
  python3 brute.py pterodactyl.htb 100 --vhost 10.129.1.46 --vhost-scheme https
  python3 brute.py pterodactyl.htb 100 --vhost 10.129.1.46 --filter-size 50
  python3 brute.py pterodactyl.htb 100 --vhost 10.129.1.46 --match-codes 200,302
"""
    )

    parser.add_argument("domain",  help="Target domain (e.g. pterodactyl.htb or example.com)")
    parser.add_argument("threads", type=int, default=100, nargs="?",
                        help="Thread count (default: 100)")

    parser.add_argument("--print-only", action="store_true",
                        help="Print candidates without resolving (pipe to dnsx)")

    vhost_grp = parser.add_argument_group(
        "VHost mode  (use when DNS doesn't work — HTB / .htb / .thm / .local)"
    )
    vhost_grp.add_argument(
        "--vhost", metavar="IP", default=None,
        help="Enable VHost brute-force: hit this IP with Host: headers instead of DNS"
    )
    vhost_grp.add_argument(
        "--vhost-port", type=int, default=80, metavar="PORT",
        help="HTTP port to probe in vhost mode (default: 80)"
    )
    vhost_grp.add_argument(
        "--vhost-scheme", default=None, choices=["http", "https"], metavar="SCHEME",
        help="Force http or https (default: http for 80, https for 443)"
    )
    vhost_grp.add_argument(
        "--vhost-timeout", type=int, default=10, metavar="SEC",
        help="Request timeout in vhost mode (default: 10)"
    )
    vhost_grp.add_argument(
        "--filter-size", type=int, default=None, metavar="BYTES",
        help="Hide vhost responses within N bytes of baseline size (removes wildcard noise)"
    )
    vhost_grp.add_argument(
        "--size-delta", type=int, default=20, metavar="BYTES",
        help="Byte tolerance for baseline/wildcard comparison (default: 20)"
    )
    vhost_grp.add_argument(
        "--filter-codes", default="404", metavar="CODES",
        help="Comma-separated HTTP codes to hide (default: 404)"
    )
    vhost_grp.add_argument(
        "--match-codes", default=None, metavar="CODES",
        help="Only show these HTTP codes, e.g. --match-codes 200,302"
    )

    args   = parser.parse_args()
    domain  = args.domain.lower().strip()
    threads = args.threads

    candidates = [f"{w}.{domain}" for w in WORDLIST]

    if args.vhost:
        ip     = args.vhost
        port   = args.vhost_port
        scheme = args.vhost_scheme or ("https" if port == 443 else "http")
        timeout = args.vhost_timeout

        filter_codes: set = set()
        for c in (args.filter_codes or "").split(","):
            try: filter_codes.add(int(c.strip()))
            except ValueError: pass

        match_codes = None
        if args.match_codes:
            match_codes = set()
            for c in args.match_codes.split(","):
                try: match_codes.add(int(c.strip()))
                except ValueError: pass

        print(
            f"[vhost] Mode      : VHost brute-force (bypassing DNS)",
            file=sys.stderr
        )
        print(
            f"[vhost] Target    : {scheme}://{ip}:{port}  Host: *.{domain}",
            file=sys.stderr
        )
        print(
            f"[vhost] Wordlist  : {len(WORDLIST)} candidates  |  Threads: {threads}",
            file=sys.stderr
        )

        print(f"[vhost] Grabbing baseline for {domain} ...", file=sys.stderr)
        base_code, base_len, wild_len = _vhost_baseline(ip, port, scheme, domain, timeout)

        if base_code is None:
            print(
                f"[vhost] ERROR: Cannot reach {scheme}://{ip}:{port} — "
                f"check VPN, IP, and port.",
                file=sys.stderr
            )
            sys.exit(1)

        print(
            f"[vhost] Baseline  : status={base_code}  size={base_len}B",
            file=sys.stderr
        )
        if wild_len is not None:
            print(
                f"[vhost] Wildcard  : size={wild_len}B  "
                f"(auto-filtering responses within {args.size_delta}B of this)",
                file=sys.stderr
            )
        else:
            print(
                f"[vhost] Wildcard  : none detected — all differing responses shown",
                file=sys.stderr
            )

        if args.filter_size is not None:
            print(
                f"[vhost] Filter    : hiding responses within {args.filter_size}B "
                f"of baseline ({base_len}B)",
                file=sys.stderr
            )

        print("", file=sys.stderr)

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {
                ex.submit(
                    _probe_vhost,
                    ip, port, scheme, domain, w,
                    base_code, base_len, wild_len,
                    args.filter_size, args.size_delta,
                    filter_codes, match_codes, timeout
                ): w for w in WORDLIST
            }
            for fut in concurrent.futures.as_completed(futures):
                if _shutdown:
                    break
                try:
                    res = fut.result()
                    if res:
                        fqdn, code, length = res
                        print(fqdn, flush=True)
                        print(
                            f"[vhost] FOUND  {fqdn}  [{code}]  {length}B",
                            file=sys.stderr
                        )
                        found.append((fqdn, code, length))
                except Exception:
                    pass

        if _shutdown:
            print("\n[vhost] Interrupted.", file=sys.stderr)

        print("", file=sys.stderr)
        if found:
            print(f"[vhost] ── {len(found)} VHost(s) found ──", file=sys.stderr)
            for fqdn, code, length in found:
                print(f"[vhost]   → {fqdn}  [{code}]  {length}B", file=sys.stderr)
            print("", file=sys.stderr)
            print(f"[vhost] Add to /etc/hosts:", file=sys.stderr)
            for fqdn, _, _ in found:
                print(f"[vhost]   {ip}  {fqdn}", file=sys.stderr)
        else:
            print("[vhost] No new vhosts found.", file=sys.stderr)
            print("[vhost] Tips:", file=sys.stderr)
            print("[vhost]   · Add --filter-size 50  (loosen size filter)", file=sys.stderr)
            print("[vhost]   · Add --size-delta 50", file=sys.stderr)
            print("[vhost]   · Try --match-codes 200,301,302,403", file=sys.stderr)
            print(f"[vhost]   · Try a different port: --vhost-port 8080", file=sys.stderr)
        return


    if args.print_only:
        for c in candidates:
            print(c)
        return

    wc_ips = wildcard_check_dns(domain)
    if wc_ips:
        print(f"[brute] Wildcard DNS detected ({wc_ips}) — filtering...", file=sys.stderr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve, c): c for c in candidates}
        for fut in concurrent.futures.as_completed(futures):
            if _shutdown:
                break
            try:
                result = fut.result()
                if result:
                    print(result, flush=True)
            except Exception:
                pass

    if _shutdown:
        print("\n[brute] Interrupted.", file=sys.stderr)


if __name__ == "__main__":
    main()
