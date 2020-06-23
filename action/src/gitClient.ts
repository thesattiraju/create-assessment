import * as core from '@actions/core';
import * as util from 'util';
import { WebRequest, WebResponse, sendRequest, StatusCodes } from "./client";

export class GitHubClient {
    constructor(repository: string, token: string) {
        this._repository = repository;
        this._token = token;
    }

    public async getCheckRuns(commitId: string): Promise<any[]> {
        const checkRunUrl = `https://api.github.com/repos/${this._repository}/commits/${commitId}/check-runs`;
        const webRequest = new WebRequest();
        webRequest.method = "GET";
        webRequest.uri = checkRunUrl;
        webRequest.headers = {
            Authorization: `token ${this._token}`,
            Accept: 'application/vnd.github.antiope-preview+json'
        };

        const response: WebResponse = await sendRequest(webRequest);
        if (response.statusCode != StatusCodes.OK) {
            throw Error(`Statuscode: ${response.statusCode}, StatusMessage: ${response.statusMessage}, Url: ${checkRunUrl}, token:${this._token}`);
        }
        return response.body;
    }

    private _repository: string;
    private _token: string;
}