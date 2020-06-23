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
const client_1 = require("./client");
class GitHubClient {
    constructor(repository, token) {
        this._repository = repository;
        this._token = token;
    }
    getCheckRuns(commitId) {
        return __awaiter(this, void 0, void 0, function* () {
            const checkRunUrl = `https://api.github.com/repos/${this._repository}/commits/${commitId}/check-runs`;
            const webRequest = new client_1.WebRequest();
            webRequest.method = "GET";
            webRequest.uri = checkRunUrl;
            webRequest.headers = {
                Authorization: `token ${this._token}`,
                Accept: 'application/vnd.github.antiope-preview+json'
            };
            const response = yield client_1.sendRequest(webRequest);
            if (response.statusCode != client_1.StatusCodes.OK) {
                throw Error(`Statuscode: ${response.statusCode}, StatusMessage: ${response.statusMessage}, Url: ${checkRunUrl}, token:${this._token}`);
            }
            return response.body;
        });
    }
}
exports.GitHubClient = GitHubClient;
