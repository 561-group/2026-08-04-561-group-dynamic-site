import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative, resolve, sep } from "node:path";

import ts from "typescript";
import { semanticId } from "@red-cup-engineering/typed-resource-catalog";

const SOURCE_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"]);
const SKIP_DIRECTORIES = new Set([".git", ".tmp", "coverage", "data", "dist", "node_modules"]);

export async function observeWorkspaceApiSurface(workspaceRoot, packageAdmissions) {
  const symbols = [];
  const packages = [];
  for (const admission of packageAdmissions) {
    const directory = resolve(String(admission.path ?? ""));
    const packagePath = portable(relative(workspaceRoot, directory));
    const packageSymbols = [];
    for (const file of await sourceFiles(join(directory, "src"))) {
      const text = await readFile(file, "utf8");
      const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, scriptKind(file));
      for (const declaration of exportedDeclarations(source)) {
        const body = {
          type: "NodeWorkspaceApiSymbol",
          version: 1,
          package: admission.name,
          packagePath,
          module: moduleName(directory, file),
          file: portable(relative(workspaceRoot, file)),
          name: declaration.name,
          kind: declaration.kind,
          signature: declaration.signature,
          documented: declaration.documented,
        };
        const id = semanticId(body);
        packageSymbols.push(Object.freeze({ ...body, id, locus: `symbol:${id}` }));
      }
    }
    packageSymbols.sort(compareSymbols);
    symbols.push(...packageSymbols);
    packages.push(Object.freeze({ name: admission.name, path: packagePath, symbols: packageSymbols.length }));
  }
  const body = {
    type: "NodeWorkspaceApiSurfaceReceipt",
    version: 1,
    packages: packages.sort((left, right) => left.name.localeCompare(right.name)),
    symbols: symbols.sort(compareSymbols),
  };
  return Object.freeze({ ...body, id: semanticId(body) });
}

async function sourceFiles(directory, output = []) {
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); }
  catch (error) { if (error?.code === "ENOENT") return output; throw error; }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRECTORIES.has(entry.name)) await sourceFiles(path, output);
    } else if (SOURCE_EXTENSIONS.has(extname(entry.name)) && !/\.(?:test|spec)\.[mc]?[jt]sx?$/u.test(entry.name) && !/\.d\.[mc]?ts$/u.test(entry.name)) {
      output.push(path);
    }
  }
  return output.sort();
}

function exportedDeclarations(source) {
  const declarations = [];
  source.forEachChild((node) => {
    if (!isExported(node)) return;
    if (ts.isFunctionDeclaration(node) && node.name) declarations.push(readDeclaration(node.name.text, "function", functionHead(node, source), node, source));
    else if (ts.isClassDeclaration(node) && node.name) declarations.push(readDeclaration(node.name.text, "class", blockHead(node, source), node, source));
    else if (ts.isInterfaceDeclaration(node)) declarations.push(readDeclaration(node.name.text, "interface", blockHead(node, source), node, source));
    else if (ts.isTypeAliasDeclaration(node)) declarations.push(readDeclaration(node.name.text, "type-alias", node.getText(source), node, source));
    else if (ts.isVariableStatement(node)) {
      for (const declaration of node.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) continue;
        const callable = declaration.initializer && (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer));
        declarations.push(readDeclaration(declaration.name.text, callable ? "function" : "variable", variableHead(node, declaration, source), node, source));
      }
    }
  });
  return declarations;
}

function isExported(node) {
  return node.modifiers?.some(({ kind }) => kind === ts.SyntaxKind.ExportKeyword) === true;
}

function readDeclaration(name, kind, signature, node, source) {
  const ranges = ts.getLeadingCommentRanges(source.text, node.getFullStart()) ?? [];
  const documented = ranges.some(({ kind: commentKind, pos }) => commentKind === ts.SyntaxKind.MultiLineCommentTrivia && source.text.startsWith("/**", pos));
  return Object.freeze({ name, kind, signature: compact(signature), documented });
}

function functionHead(node, source) {
  return source.text.slice(node.getStart(source), node.body?.getStart(source) ?? node.getEnd());
}

function blockHead(node, source) {
  const text = node.getText(source);
  const brace = text.indexOf("{");
  return brace < 0 ? text : text.slice(0, brace);
}

function variableHead(statement, declaration, source) {
  const keyword = statement.declarationList.flags & ts.NodeFlags.Const ? "const" : statement.declarationList.flags & ts.NodeFlags.Let ? "let" : "var";
  const initializer = declaration.initializer;
  if (initializer && (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer))) {
    const generics = initializer.typeParameters ? `<${initializer.typeParameters.map((parameter) => parameter.getText(source)).join(", ")}>` : "";
    const parameters = initializer.parameters.map((parameter) => parameter.getText(source)).join(", ");
    const returns = initializer.type ? `: ${initializer.type.getText(source)}` : "";
    return `export ${keyword} ${declaration.name.getText(source)} = ${generics}(${parameters})${returns} => …`;
  }
  return `export ${keyword} ${declaration.name.getText(source)}${declaration.type ? `: ${declaration.type.getText(source)}` : ""}`;
}

function moduleName(packageDirectory, file) {
  const value = portable(relative(join(packageDirectory, "src"), file)).replace(/\.[^.]+$/u, "").replace(/\/index$/u, "");
  return value === "index" || value === "" ? "." : value;
}

function scriptKind(file) {
  if (/\.tsx$/u.test(file)) return ts.ScriptKind.TSX;
  if (/\.jsx$/u.test(file)) return ts.ScriptKind.JSX;
  if (/\.[mc]?ts$/u.test(file)) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function compareSymbols(left, right) {
  return left.package.localeCompare(right.package) || left.module.localeCompare(right.module) || left.name.localeCompare(right.name) || left.signature.localeCompare(right.signature);
}

function compact(value, max = 320) {
  const text = value.replace(/\s+/gu, " ").trim();
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

function portable(path) { return path.split(sep).join("/"); }
