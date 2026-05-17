type Props = {
    request: {
        body: {
            title: string;
        };
    };
};

export function Preview({ request }: Props) {
    const el = <section className="preview">Preview</section>;
    document.write(request.body.title); // js/taint-xss-innerhtml
    return el;
}
