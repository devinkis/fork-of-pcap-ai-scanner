import fs from 'fs';
import path from 'path';
import recast from 'recast';
import * as babelParser from '@babel/parser';
import traverse from '@babel/traverse';
import * as t from '@babel/types';

const PROJECT_ROOT = path.resolve(__dirname, '..');
const API_DIR = path.join(PROJECT_ROOT, 'app/api');
const HOF_IMPORT_PATH = '@/lib/withApiLogging';
const HOF_NAME = 'withApiLogging';

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];

function processFile(filePath: string) {
  console.log(`[WRAP_HANDLERS] Processing: ${path.relative(PROJECT_ROOT, filePath)}`);
  const code = fs.readFileSync(filePath, 'utf-8');

  const ast = recast.parse(code, {
    parser: {
      parse(source: string) {
        return babelParser.parse(source, {
          sourceType: 'module',
          plugins: ['typescript', 'jsx'],
          tokens: true,
        });
      },
    },
  });

  let hofImportExists = false;
  let fileModified = false;

  traverse(ast as any, {
    ImportDeclaration(path) {
      if (path.node.source.value === HOF_IMPORT_PATH) {
        path.node.specifiers.forEach(specifier => {
          if (
            t.isImportSpecifier(specifier) &&
            t.isIdentifier(specifier.imported) &&
            specifier.imported.name === HOF_NAME
          ) {
            hofImportExists = true;
          }
        });
      }
    },
  });

  if (!hofImportExists) {
    const hofImportDeclaration = t.importDeclaration(
      [t.importSpecifier(t.identifier(HOF_NAME), t.identifier(HOF_NAME))],
      t.stringLiteral(HOF_IMPORT_PATH)
    );

    const body = ast.program.body;
    let lastImportIndex = -1;
    for (let i = body.length - 1; i >= 0; i--) {
      if (t.isImportDeclaration(body[i])) {
        lastImportIndex = i;
        break;
      }
    }
    body.splice(lastImportIndex + 1, 0, hofImportDeclaration);
    console.log(`  [WRAP_HANDLERS] Added HOF import.`);
    fileModified = true;
  }

  traverse(ast as any, {
    ExportNamedDeclaration(path) {
      const node = path.node;
      let declarationModified = false;

      if (node.declaration && t.isFunctionDeclaration(node.declaration) && node.declaration.id) {
        const functionName = node.declaration.id.name;
        if (HTTP_METHODS.includes(functionName.toUpperCase())) {
          const currentExportCode = recast.print(node).code;
          if (currentExportCode.includes(`${HOF_NAME}(`) && currentExportCode.includes(functionName)) {
            return;
          }

          const originalFunctionNode = node.declaration;
          const tempOriginalHandlerName = `__original_${functionName}_handler`;

          const renamedFunctionDeclaration = t.functionDeclaration(
            t.identifier(tempOriginalHandlerName),
            originalFunctionNode.params,
            originalFunctionNode.body,
            originalFunctionNode.generator,
            originalFunctionNode.async
          );

          const auditActionConfig = getAuditActionForRoute(filePath, functionName.toUpperCase());
          const hofArgs = [t.identifier(tempOriginalHandlerName)];
          if (auditActionConfig) {
            hofArgs.push(
              t.objectExpression([
                t.objectProperty(t.identifier('action'), t.stringLiteral(auditActionConfig.action)),
              ])
            );
          }

          const callExpression = t.callExpression(t.identifier(HOF_NAME), hofArgs);
          const newVariableDeclarator = t.variableDeclarator(t.identifier(functionName), callExpression);
          const newExportDeclaration = t.exportNamedDeclaration(
            t.variableDeclaration('const', [newVariableDeclarator])
          );

          path.replaceWithMultiple([renamedFunctionDeclaration, newExportDeclaration]);
          console.log(`  [WRAP_HANDLERS] Wrapped function export ${functionName}.`);
          declarationModified = true;
          fileModified = true;
        }
      } else if (node.declaration && t.isVariableDeclaration(node.declaration)) {
        node.declaration.declarations.forEach(declarator => {
          if (t.isVariableDeclarator(declarator) && t.isIdentifier(declarator.id)) {
            const varName = declarator.id.name;
            if (HTTP_METHODS.includes(varName.toUpperCase())) {
              if (
                declarator.init &&
                t.isCallExpression(declarator.init) &&
                t.isIdentifier(declarator.init.callee) &&
                declarator.init.callee.name === HOF_NAME
              ) {
                return;
              }

              if (
                declarator.init &&
                (t.isArrowFunctionExpression(declarator.init) || t.isFunctionExpression(declarator.init))
              ) {
                const originalFunctionExpression = declarator.init;
                const auditActionConfig = getAuditActionForRoute(filePath, varName.toUpperCase());
                const hofArgs = [originalFunctionExpression];
                if (auditActionConfig) {
                  hofArgs.push(
                    t.objectExpression([
                      t.objectProperty(t.identifier('action'), t.stringLiteral(auditActionConfig.action)),
                    ])
                  );
                }
                declarator.init = t.callExpression(t.identifier(HOF_NAME), hofArgs);
                console.log(`  [WRAP_HANDLERS] Wrapped variable export ${varName}.`);
                declarationModified = true;
                fileModified = true;
              }
            }
          }
        });
      }
    },
  });

  if (fileModified) {
    const outputOptions = { quote: 'single', trailingComma: true };
    const outputCode = recast.print(ast, outputOptions).code;
    fs.writeFileSync(filePath, outputCode, 'utf-8');
    console.log(`  [WRAP_HANDLERS] Successfully updated ${filePath}`);
  }
}

function getAuditActionForRoute(filePath: string, httpMethod: string): { action: string } | null {
  const relativePath = path.relative(API_DIR, filePath);

  if (relativePath.startsWith('admin/users')) {
    if (httpMethod === 'POST' && !relativePath.includes('[id]')) return { action: 'admin_create_user' };
    if (relativePath.includes('[id]')) {
      if (httpMethod === 'PUT') return { action: 'admin_update_user' };
      if (httpMethod === 'DELETE') return { action: 'admin_delete_user' };
    }
  } else if (relativePath.startsWith('auth/login') && httpMethod === 'POST') {
    return { action: 'user_login_attempt' };
  } else if (relativePath.startsWith('auth/logout') && httpMethod === 'POST') {
    return { action: 'user_logout_attempt' };
  } else if (relativePath.startsWith('upload-pcap') && httpMethod === 'POST') {
    return { action: 'pcap_file_upload_attempt' };
  } else if (relativePath.startsWith('delete-pcap') && httpMethod === 'DELETE') {
    return { action: 'user_delete_single_analysis_attempt' };
  }

  return null;
}

function walkDir(dir: string, callback: (filePath: string) => void) {
  fs.readdirSync(dir).forEach(f => {
    if (['node_modules', '.next', '.vercel'].includes(f)) return;
    const dirPath = path.join(dir, f);
    try {
      const stat = fs.statSync(dirPath);
      if (stat.isDirectory()) {
        walkDir(dirPath, callback);
      } else {
        callback(dirPath);
      }
    } catch {
      // Skip broken symlinks or inaccessible files
    }
  });
}

console.log('[WRAP_HANDLERS] Starting API handler wrapping process...');
try {
  walkDir(API_DIR, filePath => {
    if (filePath.endsWith('route.ts') || filePath.endsWith('route.js')) {
      if (filePath.includes('withApiLogging.ts') || filePath.includes('siem-logger.ts')) return;
      processFile(filePath);
    }
  });
} catch (error) {
  console.error('[WRAP_HANDLERS] Critical error during directory walk or processing:', error);
  process.exit(1);
}
console.log('[WRAP_HANDLERS] API handler wrapping process finished.');
