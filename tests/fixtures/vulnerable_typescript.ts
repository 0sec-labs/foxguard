interface RenderRequest {
    payload: string;
}

export function render(request: RenderRequest): unknown {
    return eval(request.payload as string);
}
