type Props = {
    title: string;
};

export function Preview({ title }: Props) {
    const el = <section className="preview">{title}</section>;
    document.write("<h1>Preview</h1>");
    return el;
}
