# Running the target on your own Kubernetes namespace

Two options, depending on how realistic you need this to be.

## Option A: single-pod target (quick, simple)

One pod running the same all-in-one target as local Docker mode. Good
for a fast check that your namespace access works. See the original
setup below this section.

## Option B: the real four-service architecture (recommended for a workshop)

A single pod is not a supply chain - it's one box. This option deploys
an actual topology: a **registry** (the tool store), an **identity**
service, a **gateway** in front of both that does real-time scanning and
blocking, and an **agent-runtime** that independently discovers and uses
tools - a genuinely separate consumer, not the attacker faking both
sides of the interaction.

```bash
cd k8s
./deploy_full_architecture.sh
./port-forward-gateway.sh          # separate terminal
cd ../harness
python run_exercise.py --target http://localhost:8000 --mode compare
```

### What's actually different about this option

- **registry** and **identity** are backend-only - a Kubernetes
  NetworkPolicy blocks anything except the gateway from reaching them.
  There is no direct-attack-the-backend path in this topology, the same
  way there wouldn't be in a real deployment with an API gateway in
  front of an internal service.
- **gateway** is real, in-line PREVENTION, not just detection:
  - Rejects a tool registration outright (HTTP 403) if its
    implementation contains an obviously dangerous pattern - before it
    ever reaches the registry
  - Compares every description update against the tool's previous
    description; if the update introduces a new suspicious phrase, the
    tool is quarantined immediately - hidden from tool listings and
    blocked from being called, in real time
  - Rate-limits identity/credential usage per credential, independent
    of whatever the UC2 blue team behavioral detector finds afterward
  - This is a genuinely separate control from `blue_team/` and
    `ai_blue_team/` elsewhere in this lab. Those are detection (after
    the fact, reading logs). This is prevention (in the request path).
    A real security architecture has both - defense in depth - and this
    demonstrates the distinction instead of only having one layer.
- **agent-runtime** is a real, independent background consumer - it
  polls the gateway on its own schedule and calls whatever tools it
  finds, with no connection to the red team. This is what makes UC1 an
  actual supply-chain scenario: the attacker poisons a tool, and a
  completely separate, unaware service is the one that triggers it.
- **NetworkPolicies** enforce all of this - default-deny-all as the
  baseline, with explicit narrow exceptions per component
  (`k8s/manifests/02-networkpolicies.yaml`).
- **ServiceAccounts per component** - the Kubernetes-native equivalent
  of what Entra Agent ID / AgentCore Identity give you in the cloud:
  each workload gets its own distinct identity.

### Verified before being handed to you

Every one of these was tested live, with real HTTP traffic through a
running gateway proxying to real registry/identity services - not just
read and assumed correct:

| Test | Result |
|---|---|
| Register a benign tool through the gateway | Succeeds |
| Register a tool with `cat /etc/passwd` in it | **Blocked, HTTP 403**, never reaches registry |
| Rug-pull an approved tool's description | Gateway detects it, quarantines the tool |
| List tools right after | Quarantined tool **disappears from the list** |
| Try to call the quarantined tool anyway | **Blocked, HTTP 403** |
| Rate limit: 5 rapid identity/use calls with the same credential | First 3 succeed (200), **4th and 5th blocked (429)** |
| Combined `/admin/logs` across all 3 services | Correctly aggregates and sorts events from registry, identity, and gateway |

**Not verified:** actual deployment to a live Kubernetes cluster - this
was built without cluster access. The application logic above was
proven correct by running the exact same code locally with the services
talking to each other over `localhost`, wired together exactly the way
the K8s Services will wire them together in your cluster. The YAML
manifests themselves were validated for correctness (parse cleanly,
correct `kind`/structure) but not applied against a real API server.
Run `./deploy_full_architecture.sh` once yourself before it's in front
of anyone.

### The one thing you should test yourself, live, on stage

```bash
kubectl port-forward -n purple-team-lab svc/registry 8001:8000 &
curl http://localhost:8001/healthz
```

If your cluster's CNI enforces NetworkPolicy on port-forwarded traffic
(most modern ones do - Calico, Cilium), this should hang or refuse.
If it succeeds, your NetworkPolicies aren't being enforced the way this
architecture assumes - worth knowing before you tell an audience "the
backend is unreachable directly."

---

# The single-pod option (Option A), full detail

## Why this needs a bit more than "just deploy it"

The local Docker Compose target and the harness share a disk (a volume
mount), so the harness can read the target's event log directly. A pod in a
cluster doesn't share a disk with your laptop. To make this work, two things
were added:

1. A `GET /admin/logs` endpoint on the target service (see `target/app.py`)
   that returns everything it has logged, as JSON.
2. The harness auto-detects a non-local `--target` URL and, right after the
   attack finishes, fetches that endpoint and writes the real events to its
   own local log before running detection - see `sync_remote_logs()` in
   `harness/run_exercise.py`. Nothing changes for local targets; this is a
   no-op unless `--target` points somewhere other than localhost/127.0.0.1.

Verified: real event registered against the target, fetched back over the
same code path this uses, and confirmed the harness's local log ends up
with the identical event. Not run against a live cluster from where this
was built (no cluster access in that environment) - test the actual
`kubectl apply` against your real lab before relying on it live.

## Why no container registry is needed

`k8s/01-deployment.yaml` uses the plain `python:3.12-slim` image and mounts
your actual `target/app.py`, `logging_utils.py`, and `requirements.txt` in
via a ConfigMap - generated fresh from your real files every time you run
`deploy.sh`, so it can never silently drift out of sync with the code you're
testing. This means the only permissions you need in your namespace are the
ordinary ones: create a Namespace, ConfigMap, Deployment, and Service. No
`docker build`, no `docker push`, no registry credentials.

Trade-off: the pod runs `pip install` on startup instead of using a
pre-built image, so it takes a few seconds longer to become ready the first
time. Worth it for zero registry dependency in a lab you don't control the
infrastructure of.

## Setup

```bash
cd k8s
./deploy.sh
```

This creates the namespace (default `purple-team-lab` — override with
`K8S_NAMESPACE=your-namespace ./deploy.sh` if your lab assigns you a
specific one), generates the ConfigMap, applies the Deployment and Service,
and waits for the pod to become ready.

## Connect the harness to it

```bash
# In one terminal, leave this running:
./port-forward.sh

# In another terminal:
cd ../harness
python run_exercise.py --target http://localhost:8000 --mode scripted
python run_exercise.py --target http://localhost:8000 --mode compare --runs 5
```

Everything else — `--mode`, `--triage`, `--enrich-crowdstrike`,
`--forward-splunk` — works exactly the same as local mode. The only
difference is where the target actually runs.

## Teardown

```bash
./teardown.sh
```

One command, deletes the whole namespace. If your lab only gave you access
to this one namespace, this is the complete cleanup.

## If your lab is more restrictive

Some things that might not match your specific lab's setup, and what to
adjust:

- **No ability to create a Namespace object** (already assigned one): edit
  `K8S_NAMESPACE` to your assigned namespace name and remove the namespace
  creation line from `deploy.sh` — everything else targets `-n
  $K8S_NAMESPACE` already.
- **NetworkPolicy required / default-deny namespace**: you may need to add
  an explicit NetworkPolicy allowing ingress on port 8000 from wherever
  `kubectl port-forward` originates (usually the API server, which
  NetworkPolicies generally can't restrict for port-forward specifically —
  check your cluster's actual behavior).
- **No egress to PyPI from inside the cluster**: the pod's `pip install`
  step needs outbound access to PyPI. If your lab blocks that, you'll need
  to switch to the Dockerfile-based approach instead (already in
  `target/Dockerfile`) and build the image somewhere with PyPI access, then
  push it to whatever registry your lab does allow — swap the `image:` line
  in `01-deployment.yaml` accordingly.
