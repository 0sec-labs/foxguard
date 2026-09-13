/** Coordinates scan ownership before asynchronous discovery or process creation. */
export class ScanController {
  private readonly documents = new Map<string, AbortController>();
  private workspace?: {
    request: AbortController;
    contains: (uri: string) => boolean;
    changed: Set<string>;
  };

  startDocScan(uri: string): AbortController {
    this.cancelDocScan(uri);
    const request = new AbortController();
    this.documents.set(uri, request);
    return request;
  }

  isDocCurrent(uri: string, request: AbortController): boolean {
    return this.documents.get(uri) === request && !request.signal.aborted;
  }

  cancelDocScan(uri: string): void {
    this.documents.get(uri)?.abort();
    this.documents.delete(uri);
    if (this.workspace?.contains(uri)) {
      this.workspace.changed.add(uri);
    }
  }

  finishDocScan(uri: string, request: AbortController): void {
    if (this.documents.get(uri) === request) {
      this.documents.delete(uri);
    }
  }

  startWsScan(contains: (uri: string) => boolean): AbortController {
    this.workspace?.request.abort();
    for (const [uri, request] of this.documents) {
      if (contains(uri)) {
        request.abort();
        this.documents.delete(uri);
      }
    }
    const request = new AbortController();
    this.workspace = { request, contains, changed: new Set() };
    return request;
  }

  isWsCurrent(request: AbortController): boolean {
    return this.workspace?.request === request && !request.signal.aborted;
  }

  canPublishWorkspace(request: AbortController, uri: string): boolean {
    const workspace = this.workspace;
    return workspace !== undefined && workspace.request === request && !request.signal.aborted
      && workspace.contains(uri) && !workspace.changed.has(uri);
  }

  finishWsScan(request: AbortController): void {
    if (this.workspace?.request === request) {
      this.workspace = undefined;
    }
  }

  cancelAll(): void {
    for (const request of this.documents.values()) {
      request.abort();
    }
    this.documents.clear();
    this.workspace?.request.abort();
    this.workspace = undefined;
  }

  get running(): boolean {
    if (this.workspace && !this.workspace.request.signal.aborted) {
      return true;
    }
    for (const request of this.documents.values()) {
      if (!request.signal.aborted) {
        return true;
      }
    }
    return false;
  }
}
