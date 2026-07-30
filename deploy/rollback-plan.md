# Rollback Plan

## Previous Stable Version
Tag: v1.0.0

## Rollback Method
1. Revert to previous git tag: `git checkout v1.0.0`
2. Re-deploy via CI/CD: trigger `deploy.yml` workflow on the tag
3. Restore database snapshot if schema changes were involved

## Rollback Owner
DevOps

## Decision Threshold
Any P0 production issue (site down, broken checkout, incorrect legal info, data exposure)

## Maximum Response Time
15 minutes from detection to rollback initiation
