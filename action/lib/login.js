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
function createAssessmentMetadata(azureSessionToken, subscriptionId, managementEndpointUrl) {
    return new Promise((resolve, reject) => {
        console.log("Creating Metadata");
        var webRequest = new client_1.WebRequest();
        webRequest.method = 'PUT';
        webRequest.uri = `${managementEndpointUrl}/subscriptions/${subscriptionId}/providers/Microsoft.Security/assessmentMetadata/5a9c8d2c-1a7e-469e-9b93-04ad795f04f0?api-version=2020-01-01`;
        webRequest.headers = {
            'Authorization': 'Bearer ' + azureSessionToken,
            'Content-Type': 'application/json; charset=utf-8'
        };
        webRequest.body = JSON.stringify({
            "properties": {
                "displayName": "Assessments from GitHub action",
                "remediationDescription": "Check with the pipeline create for remediation steps",
                "category": [
                    "Compute"
                ],
                "severity": "Medium",
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
function createAssessment(azureSessionToken, subscriptionId, managementEndpointUrl) {
    let resourceGroupName = core.getInput('resource-group', { required: true });
    let clusterName = core.getInput('cluster-name', { required: true });
    let description = core.getInput('description', { required: true });
    let code = core.getInput('code', { required: true });
    return new Promise((resolve, reject) => {
        var webRequest = new client_1.WebRequest();
        webRequest.method = 'PUT';
        webRequest.uri = `${managementEndpointUrl}/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}/providers/Microsoft.ContainerService/managedClusters/${clusterName}/providers/Microsoft.Security/assessments/5a9c8d2c-1a7e-469e-9b93-04ad795f04f0?api-version=2020-01-01`;
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
                    "description": description
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
        yield createAssessmentMetadata(azureSessionToken, subscriptionId, managementEndpointUrl);
        yield createAssessment(azureSessionToken, subscriptionId, managementEndpointUrl);
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
