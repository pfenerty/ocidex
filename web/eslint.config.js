import js from "@eslint/js";
import tseslint from "typescript-eslint";
import solid from "eslint-plugin-solid/configs/typescript";
import ocidex from "./eslint-rules/ocidex.js";

export default tseslint.config(
    js.configs.recommended,
    ...tseslint.configs.recommendedTypeChecked,
    ...tseslint.configs.stylisticTypeChecked,
    {
        languageOptions: {
            parserOptions: {
                projectService: true,
                tsconfigRootDir: import.meta.dirname,
            },
        },
    },
    {
        files: ["**/*.{ts,tsx}"],
        ...solid,
    },
    {
        rules: {
            // TypeScript strict rules
            "@typescript-eslint/no-unused-vars": [
                "error",
                {
                    argsIgnorePattern: "^_",
                    varsIgnorePattern: "^_",
                    destructuredArrayIgnorePattern: "^_",
                },
            ],
            "@typescript-eslint/no-explicit-any": "error",
            "@typescript-eslint/no-non-null-assertion": "warn",
            "@typescript-eslint/consistent-type-imports": [
                "error",
                { prefer: "type-imports", fixStyle: "inline-type-imports" },
            ],
            "@typescript-eslint/consistent-type-definitions": [
                "error",
                "interface",
            ],
            "@typescript-eslint/no-unnecessary-condition": "error",
            "@typescript-eslint/strict-boolean-expressions": "warn",
            "@typescript-eslint/prefer-nullish-coalescing": "error",
            "@typescript-eslint/prefer-optional-chain": "error",
            "@typescript-eslint/no-floating-promises": "error",
            "@typescript-eslint/no-misused-promises": "error",
            "@typescript-eslint/require-await": "error",

            // General best practices
            "no-console": ["warn", { allow: ["warn", "error"] }],
            eqeqeq: ["error", "always"],
            "no-eval": "error",
            "no-implied-eval": "off",
            "@typescript-eslint/no-implied-eval": "error",
            "prefer-const": "error",
            "no-var": "error",
            // Promoted into eslint's recommended set in v10. Solid's `ref={el}`
            // is compiled into the assignment, so the rule sees only the bare
            // `let el: HTMLElement | undefined` and calls every ref binding in
            // the app dead.
            "no-unassigned-vars": "off",
            "object-shorthand": "error",
            "prefer-template": "error",
        },
    },
    {
        // Design-system contracts: which files may emit which classes and
        // elements. Each was a regex test over source; the reasons live with the
        // primitives (components/ui) they protect.
        files: ["src/**/*.tsx"],
        ignores: ["src/**/*.test.tsx"],
        plugins: { ocidex },
        rules: {
            "ocidex/class-contract": [
                "error",
                [
                    {
                        // .btn, .btn-primary, .btn-sm… but not sidebar-logout-btn.
                        pattern: "(?<![-\\w])btn(-[a-z]+)?\\b",
                        allow: ["components/ui/Button.tsx", "components/ui/ButtonGroup.tsx"],
                        message: "Use <Button>/<ButtonGroup>; only they emit the .btn classes.",
                    },
                    {
                        // index.css styles `.btn-group .btn.active`, so the container
                        // must come from the primitive that also sets `active`.
                        pattern: "(?<![-\\w])btn-group(?![-\\w])",
                        scope: "string",
                        allow: ["components/ui/ButtonGroup.tsx"],
                        message: "Use <ButtonGroup>; it is the only emitter of .btn-group.",
                    },
                    {
                        pattern: "btn-secondary",
                        scope: "string",
                        message: "No rule defines .btn-secondary; the bare .btn is the secondary button.",
                    },
                    {
                        pattern: "tab-btn|tab-active",
                        scope: "string",
                        message: "tab-btn and tab-active are not defined; use <TabBar>.",
                    },
                    {
                        pattern: "(?<![-\\w])card(-header)?(?![-\\w])",
                        allow: ["components/ui/Card.tsx", "components/ui/Modal.tsx", "components/Skeleton.tsx"],
                        message: "Use <Card>; it is the only emitter of the card markup.",
                    },
                    {
                        pattern: "(?<![-\\w])table(?![-\\w])",
                        message: "No stylesheet defines a .table class.",
                    },
                    {
                        pattern: "^(page-header|page-header-row)$",
                        allow: ["components/ui/PageHeader.tsx", "components/Skeleton.tsx"],
                        message: "Use <PageHeader>; it is the only emitter of the page-header markup.",
                    },
                ],
            ],
            "ocidex/jsx-element-contract": [
                "error",
                [
                    {
                        element: "table",
                        allow: ["components/DataTable.tsx", "components/Skeleton.tsx"],
                        message: "Use <DataTable>; it is the only place a <table> is rendered.",
                    },
                ],
            ],
        },
    },
    {
        files: ["**/*.test.{ts,tsx}"],
        rules: {
            "@typescript-eslint/unbound-method": "off",
            "@typescript-eslint/no-unsafe-assignment": "off",
        },
    },
    {
        ignores: ["dist/", "node_modules/", "*.config.js", "*.config.ts", "src/types/openapi.d.ts"],
    },
);
