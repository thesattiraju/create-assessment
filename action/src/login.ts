import * as core from '@actions/core';
import { WebRequest, WebRequestOptions, WebResponse, sendRequest } from "./client";
import * as querystring from 'querystring';

import { v4 as uuidv4 } from 'uuid';
import { GitHubClient } from './gitClient';

interface Details {
    description: string;
    remediationSteps: string;
    title: string;
}

function getAzureAccessToken(servicePrincipalId, servicePrincipalKey, tenantId, authorityUrl): Promise<string> {

    if (!servicePrincipalId || !servicePrincipalKey || !tenantId || !authorityUrl) {
        throw new Error("Not all values are present in the creds object. Ensure appId, password and tenant are supplied");
    }
    return new Promise<string>((resolve, reject) => {
        let webRequest = new WebRequest();
        webRequest.method = "POST";
        webRequest.uri = `${authorityUrl}/${tenantId}/oauth2/token/`;
        webRequest.body = querystring.stringify({
            resource: 'https://management.azure.com',
            client_id: servicePrincipalId,
            grant_type: "client_credentials",
            client_secret: servicePrincipalKey
        });
        webRequest.headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
        };

        let webRequestOptions: WebRequestOptions = {
            retriableStatusCodes: [400, 408, 409, 500, 502, 503, 504],
        };

        sendRequest(webRequest, webRequestOptions).then(
            (response: WebResponse) => {
                if (response.statusCode == 200) {
                    console.log("Got access token")
                    resolve(response.body.access_token);
                }
                else if ([400, 401, 403].indexOf(response.statusCode) != -1) {
                    reject('ExpiredServicePrincipal');
                }
                else {
                    reject('CouldNotFetchAccessTokenforAzureStatusCode');
                }
            },
            (error) => {
                reject(error)
            }
        );
    });
}

async function getContainerScanDetails() {
    const commitId = process.env['GITHUB_SHA'];
    const token = core.getInput('token');
    const client = new GitHubClient(process.env['GITHUB_REPOSITORY'], token);
    const runs = await client.getCheckRuns(commitId);

    if (!runs || runs.length == 1) return "";

    let details = "";
    console.log(runs);
    let checkRuns = runs['check_runs'];
    checkRuns.forEach((run: any) => {
        if (run && run.name && run.name.startsWith('[container-scan]')) {
            details = `${details} \n ${run.output.text}`;
        }
    });

    return `${details}`;
}

async function getDetails() {
    const run_id = process.env['GITHUB_RUN_ID'];
    const workflow = process.env['GITHUB_WORKFLOW'];
    const repo = process.env['GITHUB_REPOSITORY'];
    const run_url = `https://github.com/${repo}/actions/runs/${run_id}?check_suite_focus=true`;
    const workflow_url = `https://github.com/${repo}/actions?query=workflow%3A${workflow}`;

    const containerScanResult = await getContainerScanDetails();

    let description = "";
    let remediationSteps = "";
    if (containerScanResult.trim()) {
        remediationSteps = containerScanResult;
        description = `
        Results of running the Github container scanning action on the image deployed to this cluster. 
        You can find <a href="${workflow_url}">the workflow here</a>.
        This assessment was created from <a href="${run_url}">this workflow run</a>.`
        const details: Details = {
            remediationSteps: `${containerScanResult} \n Manual remediation:
            If possible, update base images to a version that addresses these vulnerabilities.
            If the vulnerabilities are known and acceptable, add them to the allowed list in the Github repo.`,
            description: description,
            title: "Github container scanning for deployed container images"
        };
        return details;
    }

    return {
        description: `
        This security assessment has been created from GitHub actions workflow.

        You can find <a href="${workflow_url}">the workflow here</a>.
        This assessment was created from <a href="${run_url}">this workflow run</a>.

        For mitigation take appropriate steps.`,
        remediationSteps: "Manual remediation",
        title: "Assessment from github"
    } as Details;
}


function getAssessmentName(details: Details) {
    const run_id = process.env['GITHUB_RUN_ID'];
    const workflow = process.env['GITHUB_WORKFLOW'];
    if (details.title) {
        return `${details.title} - ${workflow} - ${run_id}`
    }
    return `Assessment from GitHub Action - ${workflow} - ${run_id}`;
}

function createAssessmentMetadata(azureSessionToken: string, subscriptionId: string, managementEndpointUrl: string, metadata_guid: string, details: Details): Promise<string> {
    return new Promise<string>((resolve, reject) => {
        console.log("Creating Metadata")
        let severity = core.getInput('severity', { required: true });
        var webRequest = new WebRequest();
        webRequest.method = 'PUT';
        webRequest.uri = `${managementEndpointUrl}/subscriptions/${subscriptionId}/providers/Microsoft.Security/assessmentMetadata/${metadata_guid}?api-version=2020-01-01`;
        webRequest.headers = {
            'Authorization': 'Bearer ' + azureSessionToken,
            'Content-Type': 'application/json; charset=utf-8'
        }

        webRequest.body = JSON.stringify({
            "properties": {
                "displayName": getAssessmentName(details),
                "description": details.description,
                "remediationDescription": details.remediationSteps,
                "category": [
                    "Compute"
                ],
                "severity": severity,
                "userImpact": "Low",
                "implementationEffort": "Low",
                "assessmentType": "CustomerManaged"
            }
        });

        sendRequest(webRequest).then((response: WebResponse) => {
            console.log("Response", JSON.stringify(response));
            let accessProfile = response.body;
            if (accessProfile && accessProfile.name) {
                console.log("Successfully created assessment metadata", JSON.stringify(response.body));
                resolve(accessProfile.name);
            } else {
                reject(JSON.stringify(response.body));
            }
        }).catch(reject);
    });
}

function createAssessment(azureSessionToken: string, subscriptionId: string, managementEndpointUrl: string, metadata_guid: string, details: Details): Promise<string> {
    let resourceGroupName = core.getInput('resource-group', { required: true });
    let clusterName = core.getInput('cluster-name', { required: true });
    let code = core.getInput('code', { required: true });

    return new Promise<string>((resolve, reject) => {

        var webRequest = new WebRequest();
        webRequest.method = 'PUT';
        webRequest.uri = `${managementEndpointUrl}/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}/providers/Microsoft.ContainerService/managedClusters/${clusterName}/providers/Microsoft.Security/assessments/${metadata_guid}?api-version=2020-01-01`;
        webRequest.headers = {
            'Authorization': 'Bearer ' + azureSessionToken,
            'Content-Type': 'application/json; charset=utf-8'
        }

        webRequest.body = JSON.stringify({
            "properties": {
                "resourceDetails": {
                    "id": `${managementEndpointUrl}/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}/providers/Microsoft.ContainerService/managedClusters/${clusterName}`,
                    "source": "Azure"
                },
                "status": {
                    "cause": "Created Using a GitHub action",
                    "code": code,
                    "description": details.description
                }
            }
        });

        sendRequest(webRequest).then((response: WebResponse) => {
            console.log("Response", JSON.stringify(response));
            if (response.statusCode == 200) {
                console.log("Successfully created Assessment")
                resolve();
            } else {
                reject(JSON.stringify(response.body));
            }
        }).catch(reject);
    });
}

async function createASCAssessment(): Promise<void> {
    let creds = core.getInput('creds', { required: true });
    let credsObject: { [key: string]: string; };
    try {
        credsObject = JSON.parse(creds);
    } catch (ex) {
        throw new Error('Credentials object is not a valid JSON');
    }

    let servicePrincipalId = credsObject["clientId"];
    let servicePrincipalKey = credsObject["clientSecret"];
    let tenantId = credsObject["tenantId"];
    let authorityUrl = credsObject["activeDirectoryEndpointUrl"] || "https://login.microsoftonline.com";
    let managementEndpointUrl = credsObject["resourceManagerEndpointUrl"] || "https://management.azure.com/";
    let subscriptionId = credsObject["subscriptionId"];
    let azureSessionToken = await getAzureAccessToken(servicePrincipalId, servicePrincipalKey, tenantId, authorityUrl);

    let metadata_guid = uuidv4();

    const details: Details = await getDetails();

    await createAssessmentMetadata(azureSessionToken, subscriptionId, managementEndpointUrl, metadata_guid, details);
    await createAssessment(azureSessionToken, subscriptionId, managementEndpointUrl, metadata_guid, details);
}

async function run() {
    console.log("Creating ASC assessment")
    await createASCAssessment();
}

console.log("Run")
run().catch(core.setFailed);