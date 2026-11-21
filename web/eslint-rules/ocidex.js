// Local ESLint rules for the frontend's design-system contracts. They replace
// contract tests that regex-matched .tsx source: working on the AST, they only
// look at real class strings and real strings, so a URL or a comment on the
// same line can't hide or fake a match.
import { relative, sep } from "node:path";

/** The path of the file being linted, relative to web/src, with "/" separators. */
function srcPath(context) {
    return relative(`${context.cwd}${sep}src`, context.filename).split(sep).join("/");
}

/** Every string an expression can evaluate to, as far as it can be read statically. */
function strings(node, out = []) {
    if (!node) return out;
    switch (node.type) {
        case "Literal":
            if (typeof node.value === "string") out.push(node.value);
            break;
        case "TemplateLiteral":
            for (const q of node.quasis) out.push(q.value.cooked ?? q.value.raw);
            for (const e of node.expressions) strings(e, out);
            break;
        case "ConditionalExpression":
            strings(node.consequent, out);
            strings(node.alternate, out);
            break;
        case "LogicalExpression":
        case "BinaryExpression":
            strings(node.left, out);
            strings(node.right, out);
            break;
        case "CallExpression": // clsx(...), cn(...), [..].join(" ")
            for (const a of node.arguments) strings(a, out);
            strings(node.callee, out);
            break;
        case "MemberExpression":
            strings(node.object, out);
            break;
        case "ArrayExpression":
            for (const el of node.elements) strings(el, out);
            break;
        case "ObjectExpression": // classList={{ "btn active": cond }}
            for (const p of node.properties) {
                if (p.type !== "Property") continue;
                if (p.key.type === "Literal" && typeof p.key.value === "string") out.push(p.key.value);
                else if (p.key.type === "Identifier" && !p.computed) out.push(p.key.name);
            }
            break;
        case "JSXExpressionContainer":
            strings(node.expression, out);
            break;
        case "TSAsExpression":
        case "TSNonNullExpression":
            strings(node.expression, out);
            break;
        default:
            break;
    }
    return out;
}

const CLASS_ATTRS = new Set(["class", "className", "classList"]);

const classContract = {
    meta: {
        type: "problem",
        docs: { description: "Confine a class-name pattern to the files allowed to emit it" },
        schema: [
            {
                type: "array",
                items: {
                    type: "object",
                    properties: {
                        pattern: { type: "string" },
                        scope: { enum: ["class", "string"] },
                        allow: { type: "array", items: { type: "string" } },
                        message: { type: "string" },
                    },
                    required: ["pattern", "message"],
                    additionalProperties: false,
                },
            },
        ],
    },
    create(context) {
        const file = srcPath(context);
        const contracts = (context.options[0] ?? [])
            .filter((c) => !(c.allow ?? []).includes(file))
            .map((c) => ({ ...c, re: new RegExp(c.pattern) }));
        if (contracts.length === 0) return {};
        const check = (node, values, scope) => {
            for (const c of contracts) {
                if ((c.scope ?? "class") !== scope) continue;
                if (values.some((v) => c.re.test(v))) context.report({ node, message: c.message });
            }
        };
        return {
            JSXAttribute(node) {
                const name = node.name.type === "JSXIdentifier" ? node.name.name : "";
                if (CLASS_ATTRS.has(name)) check(node, strings(node.value), "class");
            },
            Literal(node) {
                if (typeof node.value === "string") check(node, [node.value], "string");
            },
            TemplateElement(node) {
                check(node, [node.value.cooked ?? node.value.raw], "string");
            },
        };
    },
};

const jsxElementContract = {
    meta: {
        type: "problem",
        docs: { description: "Confine a JSX element to the files allowed to render it" },
        schema: [
            {
                type: "array",
                items: {
                    type: "object",
                    properties: {
                        element: { type: "string" },
                        allow: { type: "array", items: { type: "string" } },
                        message: { type: "string" },
                    },
                    required: ["element", "message"],
                    additionalProperties: false,
                },
            },
        ],
    },
    create(context) {
        const file = srcPath(context);
        const contracts = (context.options[0] ?? []).filter((c) => !(c.allow ?? []).includes(file));
        if (contracts.length === 0) return {};
        return {
            JSXOpeningElement(node) {
                if (node.name.type !== "JSXIdentifier") return;
                for (const c of contracts) {
                    if (node.name.name === c.element) context.report({ node, message: c.message });
                }
            },
        };
    },
};

export default {
    meta: { name: "ocidex" },
    rules: { "class-contract": classContract, "jsx-element-contract": jsxElementContract },
};
