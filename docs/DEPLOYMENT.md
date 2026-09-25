# Deployment notes

This snapshot retains deployment scripts, not private host state. Review `deploy/azure/bootstrap-host.sh`, `deploy/azure/compose.yaml`, `deploy/azure/Caddyfile`, and `deploy/azure/vibesecur-api.service` before use. The scripts contain defaults for the dedicated demo host; configure your own host, DNS name, and backend environment when deploying elsewhere.

1. Use an owned Azure VM and Docker. The intended small demo capacity is 2 vCPU and 8 GiB RAM; validate the combined workload before rehearsal.
2. Install the pinned backend dependencies and build `apps/presenter`. Keep model keys and the presenter access code in a private backend environment file.
3. Configure DNS and Caddy HTTPS. Keep controller internals and model-broker endpoints private.
4. Set `VIBESECUR_DEPLOY_HOST` and `VIBESECUR_SSH_KEY` for the deployment/check scripts. SSH keys are not included.
5. Configure and measure worker, repair, and verifier admission gates using their supplied scripts. Keep their writable scopes separate. A running frontend does not prove agent or containment readiness.
6. Warm required model, image, and browser dependencies. Execute heavy jobs one at a time. Confirm the authenticated tablet flow over HTTPS.

Repair configuration must point to this checkout and the full hash from `git rev-parse repair-baseline`. Historical gate and diagnostic scripts may contain identifiers for previous demo runs; supply fresh run configuration rather than replaying stale operational identifiers.

## Cost and teardown

Check current Azure pricing and Cost Management for the selected region and resources. Compute, disk, public IP, model inference, and traffic may all incur charges. Deallocation stops VM compute billing but retains chargeable disk/IP resources. Before deleting a dedicated demo resource group, confirm its inventory and export any needed evidence. Never tear down a host during a presentation, repair, or verification job.
