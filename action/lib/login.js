"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const core = require("@actions/core");
const client_1 = require("./client");
const querystring = require("querystring");
const uuid_1 = require("uuid");
const gitClient_1 = require("./gitClient");
function getAzureAccessToken(servicePrincipalId, servicePrincipalKey, tenantId, authorityUrl) {
    if (!servicePrincipalId || !servicePrincipalKey || !tenantId || !authorityUrl) {
        throw new Error("Not all values are present in the creds object. Ensure appId, password and tenant are supplied");
    }
    return new Promise((resolve, reject) => {
        let webRequest = new client_1.WebRequest();
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
        let webRequestOptions = {
            retriableStatusCodes: [400, 408, 409, 500, 502, 503, 504],
        };
        client_1.sendRequest(webRequest, webRequestOptions).then((response) => {
            if (response.statusCode == 200) {
                console.log("Got access token");
                resolve(response.body.access_token);
            }
            else if ([400, 401, 403].indexOf(response.statusCode) != -1) {
                reject('ExpiredServicePrincipal');
            }
            else {
                reject('CouldNotFetchAccessTokenforAzureStatusCode');
            }
        }, (error) => {
            reject(error);
        });
    });
}
function getContainerScanDetails() {
    return __awaiter(this, void 0, void 0, function* () {
        const commitId = process.env['GITHUB_SHA'];
        const token = core.getInput('token');
        const client = new gitClient_1.GitHubClient(process.env['GITHUB_REPOSITORY'], token);
        const runs = yield client.getCheckRuns(commitId);
        if (!runs || runs.length == 1)
            return "";
        let details = "";
        console.log(runs);
        let checkRuns = runs['check_runs'];
        checkRuns.forEach((run) => {
            if (run && run.name && run.name.startsWith('[container-scan]')) {
                details = `${details} \n ${run.output.text}`;
            }
        });
        return `${details}`;
    });
}
function getDetails() {
    return __awaiter(this, void 0, void 0, function* () {
        const run_id = process.env['GITHUB_RUN_ID'];
        const workflow = process.env['GITHUB_WORKFLOW'];
        const repo = process.env['GITHUB_REPOSITORY'];
        const run_url = `https://github.com/${repo}/actions/runs/${run_id}?check_suite_focus=true`;
        const workflow_url = `https://github.com/${repo}/actions?query=workflow%3A${workflow}`;
        const containerScanResult = yield getContainerScanDetails();
        let description = "";
        let remediationSteps = "";
        if (containerScanResult.trim()) {
            remediationSteps = containerScanResult;
            description = `
        Results of running the Github container scanning action on the image deployed to this cluster. 
        You can find <a href="${workflow_url}">the workflow here</a>.
        This assessment was created from <a href="${run_url}">this workflow run</a>.`;
            const details = {
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
        };
    });
}
function getAssessmentName(details) {
    const run_id = process.env['GITHUB_RUN_ID'];
    const workflow = process.env['GITHUB_WORKFLOW'];
    if (details.title) {
        return `${details.title} - ${workflow} - ${run_id}`;
    }
    return `Assessment from GitHub Action - ${workflow} - ${run_id}`;
}
function createAssessmentMetadata(azureSessionToken, subscriptionId, managementEndpointUrl, metadata_guid, details) {
    return new Promise((resolve, reject) => {
        console.log("Creating Metadata");
        let severity = core.getInput('severity', { required: true });
        var webRequest = new client_1.WebRequest();
        webRequest.method = 'PUT';
        webRequest.uri = `${managementEndpointUrl}/subscriptions/${subscriptionId}/providers/Microsoft.Security/assessmentMetadata/${metadata_guid}?api-version=2020-01-01`;
        webRequest.headers = {
            'Authorization': 'Bearer ' + azureSessionToken,
            'Content-Type': 'application/json; charset=utf-8'
        };
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
        client_1.sendRequest(webRequest).then((response) => {
            console.log("Response", JSON.stringify(response));
            let accessProfile = response.body;
            if (accessProfile && accessProfile.name) {
                console.log("Successfully created assessment metadata", JSON.stringify(response.body));
                resolve(accessProfile.name);
            }
            else {
                reject(JSON.stringify(response.body));
            }
        }).catch(reject);
    });
}
function createAssessment(azureSessionToken, subscriptionId, managementEndpointUrl, metadata_guid, details) {
    let resourceGroupName = core.getInput('resource-group', { required: true });
    let clusterName = core.getInput('cluster-name', { required: true });
    let code = core.getInput('code', { required: true });
    return new Promise((resolve, reject) => {
        var webRequest = new client_1.WebRequest();
        webRequest.method = 'PUT';
        webRequest.uri = `${managementEndpointUrl}/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}/providers/Microsoft.ContainerService/managedClusters/${clusterName}/providers/Microsoft.Security/assessments/${metadata_guid}?api-version=2020-01-01`;
        webRequest.headers = {
            'Authorization': 'Bearer ' + azureSessionToken,
            'Content-Type': 'application/json; charset=utf-8'
        };
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
        client_1.sendRequest(webRequest).then((response) => {
            console.log("Response", JSON.stringify(response));
            if (response.statusCode == 200) {
                console.log("Successfully created Assessment");
                resolve();
            }
            else {
                reject(JSON.stringify(response.body));
            }
        }).catch(reject);
    });
}
function createASCAssessment() {
    return __awaiter(this, void 0, void 0, function* () {
        let creds = core.getInput('creds', { required: true });
        let credsObject;
        try {
            credsObject = JSON.parse(creds);
        }
        catch (ex) {
            throw new Error('Credentials object is not a valid JSON');
        }
        let servicePrincipalId = credsObject["clientId"];
        let servicePrincipalKey = credsObject["clientSecret"];
        let tenantId = credsObject["tenantId"];
        let authorityUrl = credsObject["activeDirectoryEndpointUrl"] || "https://login.microsoftonline.com";
        let managementEndpointUrl = credsObject["resourceManagerEndpointUrl"] || "https://management.azure.com/";
        let subscriptionId = credsObject["subscriptionId"];
        let azureSessionToken = yield getAzureAccessToken(servicePrincipalId, servicePrincipalKey, tenantId, authorityUrl);
        let metadata_guid = uuid_1.v4();
        const details = yield getDetails();
        yield createAssessmentMetadata(azureSessionToken, subscriptionId, managementEndpointUrl, metadata_guid, details);
        yield createAssessment(azureSessionToken, subscriptionId, managementEndpointUrl, metadata_guid, details);
    });
}
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        console.log("Creating ASC assessment");
        yield createASCAssessment();
    });
}
console.log("Run");
run().catch(core.setFailed);
