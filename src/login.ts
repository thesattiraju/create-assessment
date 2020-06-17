import * as core from '@actions/core';
import { issueCommand } from '@actions/core/lib/command';
import * as path from 'path';
import * as fs from 'fs';
import { WebRequest, WebRequestOptions, WebResponse, sendRequest } from "./client";
import * as querystring from 'querystring';

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

function createAssessmentMetadata(azureSessionToken: string, subscriptionId: string, managementEndpointUrl: string): Promise<string> {
    let resourceGroupName = core.getInput('resource-group', { required: true });
    let clusterName = core.getInput('cluster-name', { required: true });
    return new Promise<string>((resolve, reject) => {
        var webRequest = new WebRequest();
        webRequest.method = 'PUT';
        webRequest.uri = `${managementEndpointUrl}/subscriptions/${subscriptionId}/providers/Microsoft.Security/assessmentMetadata/5a9c8d2c-1a7e-469e-9b93-04ad795f04f0?api-version=2020-01-01`;
        webRequest.headers = {
            'Authorization': 'Bearer ' + azureSessionToken,
            'Content-Type': 'application/json; charset=utf-8'
        }

        webRequest.body = JSON.stringify({
            "properties": {
                "displayName": "Assessments from GitHub action",
                "description": "Assessments from GitHub action",
                "remediationDescription": "Check with the pipeline create for remediation steps",
                "category": [
                    "Compute"
                ],
                "severity": "Medium",
                "userImpact": "Low",
                "implementationEffort": "Low",
                "assessmentType": "VerifiedPartner"
            }
        });

        sendRequest(webRequest).then((response: WebResponse) => {
            let accessProfile = response.body;
            if (accessProfile.name) {
                console.log("Successfully created assessment metadata", JSON.stringify(response.body));
                resolve(accessProfile.name);
            } else {
                reject(JSON.stringify(response.body));
            }
        }).catch(reject);
    });
}

function createAssessment(azureSessionToken: string, subscriptionId: string, managementEndpointUrl: string): Promise<string> {
    let resourceGroupName = core.getInput('resource-group', { required: true });
    let clusterName = core.getInput('cluster-name', { required: true });
    let description = core.getInput('description', { required: true });
    let code = core.getInput('code', { required: true });

    return new Promise<string>((resolve, reject) => {
        var webRequest = new WebRequest();
        webRequest.method = 'PUT';
        webRequest.uri = `${managementEndpointUrl}/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}/providers/Microsoft.ContainerService/managedClusters/${clusterName}/providers/Microsoft.Security/assessments/5a9c8d2c-1a7e-469e-9b93-04ad795f04f0?api-version=2020-01-01`;
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
                    "description": description
                }
            }
        });

        sendRequest(webRequest).then((response: WebResponse) => {
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

    await createAssessmentMetadata(azureSessionToken, subscriptionId, managementEndpointUrl);
    await createAssessment(azureSessionToken, subscriptionId, managementEndpointUrl);
}

async function run() {
    await createASCAssessment();
}

run().catch(core.setFailed);