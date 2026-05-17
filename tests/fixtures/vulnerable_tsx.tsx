type CardProps = {
    expression: string;
};

export function Card({ expression }: CardProps) {
    return <section>{eval(expression)}</section>;
}
