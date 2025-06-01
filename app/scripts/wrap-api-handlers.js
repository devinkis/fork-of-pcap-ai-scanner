// scripts/wrap-api-handlers.js
// const fs = require('fs');
// const path = require('path');
const recast = require('recast');
const babelParser = require('@babel/parser'); // Ganti nama agar tidak bentrok dengan variabel 'parser'
const traverse = require('@babel/traverse').default;
const t = require('@babel/types');

const PROJECT_ROOT = path.resolve(__dirname, '..'); // Asumsi skrip ada di ./scripts/
const API_DIR = path.join(PROJECT_ROOT, 'app/api');
const HOF_IMPORT_PATH = '@/lib/withApiLogging'; // Path ke HOF Anda
const HOF_NAME = 'withApiLogging';

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];

function processFile(filePath) {
  console.log(`[WRAP_HANDLERS] Processing: ${path.relative(PROJECT_ROOT, filePath)}`);
  const code = fs.readFileSync(filePath, 'utf-8');

  const ast = recast.parse(code, {
    parser: {
      parse(source) {
        return babelParser.parse(source, {
          sourceType: 'module',
          plugins: ['typescript', 'jsx'], // Tambahkan 'decorators-legacy' atau 'decorators' jika Anda menggunakan decorator
          tokens: true, // Recast mungkin memerlukan token
        });
      },
    },
  });

  let hofImportExists = false;
  let fileModified = false;

  traverse(ast, {
    ImportDeclaration(path) {
      if (path.node.source.value === HOF_IMPORT_PATH) {
        path.node.specifiers.forEach(specifier => {
          if (t.isImportSpecifier(specifier) && t.isIdentifier(specifier.imported) && specifier.imported.name === HOF_NAME) {
            hofImportExists = true;
          }
        });
      }
    }
  });

  if (!hofImportExists) {
    const hofImportDeclaration = t.importDeclaration(
      [t.importSpecifier(t.identifier(HOF_NAME), t.identifier(HOF_NAME))],
      t.stringLiteral(HOF_IMPORT_PATH)
    );
    // Sisipkan impor baru setelah impor yang sudah ada, atau di paling atas jika tidak ada impor
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

  traverse(ast, {
    ExportNamedDeclaration(path) {
      const node = path.node;
      let declarationModified = false;

      // Kasus: export async function GET(...) {}
      if (node.declaration && t.isFunctionDeclaration(node.declaration) && node.declaration.id) {
        const functionName = node.declaration.id.name;
        if (HTTP_METHODS.includes(functionName.toUpperCase())) {
          // Cek sederhana agar tidak membungkus dua kali
          const currentExportCode = recast.print(node).code;
          if (currentExportCode.includes(`${HOF_NAME}(`) && currentExportCode.includes(functionName)) {
            // console.log(`  [WRAP_HANDLERS] Function ${functionName} seems already wrapped. Skipping.`);
            return;
          }

          const originalFunctionNode = node.declaration;
          const tempOriginalHandlerName = `__original_${functionName}_handler`;

          // Buat AST untuk fungsi asli yang di-rename
          const renamedFunctionDeclaration = t.functionDeclaration(
            t.identifier(tempOriginalHandlerName),
            originalFunctionNode.params,
            originalFunctionNode.body,
            originalFunctionNode.generator,
            originalFunctionNode.async
          );

          // Buat AST untuk pemanggilan HOF
          // Contoh: export const GET = withApiLogging(__original_GET_handler, { action: 'get_data' });
          // Menentukan auditAction secara otomatis di sini masih sulit.
          // Anda bisa menggunakan auditAction default atau null jika HOF Anda menanganinya.
          const auditActionConfig = getAuditActionForRoute(filePath, functionName.toUpperCase());
          const hofArgs = [t.identifier(tempOriginalHandlerName)];
          if (auditActionConfig) {
            hofArgs.push(t.objectExpression([
                t.objectProperty(t.identifier('action'), t.stringLiteral(auditActionConfig.action)),
                // Tambahkan targetResourceExtractor jika ada dan bisa di-generate
            ]));
          }

          const callExpression = t.callExpression(t.identifier(HOF_NAME), hofArgs);

          // Buat variabel deklarasi baru untuk ekspor
          const newVariableDeclarator = t.variableDeclarator(t.identifier(functionName), callExpression);
          const newExportDeclaration = t.exportNamedDeclaration(
            t.variableDeclaration('const', [newVariableDeclarator])
          );

          // Ganti node ekspor yang lama dengan deklarasi fungsi asli (tidak diekspor)
          // dan tambahkan ekspor baru yang sudah dibungkus.
          path.replaceWithMultiple([renamedFunctionDeclaration, newExportDeclaration]);
          console.log(`  [WRAP_HANDLERS] Wrapped function export ${functionName}.`);
          declarationModified = true;
          fileModified = true;
        }
      }
      // Kasus: export const GET = async (...) => {}
      else if (node.declaration && t.isVariableDeclaration(node.declaration)) {
        node.declaration.declarations.forEach((declarator, index) => {
          if (t.isVariableDeclarator(declarator) && t.isIdentifier(declarator.id)) {
            const varName = declarator.id.name;
            if (HTTP_METHODS.includes(varName.toUpperCase())) {
              // Cek apakah sudah dibungkus
              if (declarator.init && t.isCallExpression(declarator.init) && t.isIdentifier(declarator.init.callee) && declarator.init.callee.name === HOF_NAME) {
                // console.log(`  [WRAP_HANDLERS] Variable ${varName} seems already wrapped. Skipping.`);
                return;
              }

              if (declarator.init && (t.isArrowFunctionExpression(declarator.init) || t.isFunctionExpression(declarator.init))) {
                const originalFunctionExpression = declarator.init;
                const auditActionConfig = getAuditActionForRoute(filePath, varName.toUpperCase());
                const hofArgs = [originalFunctionExpression];
                 if (auditActionConfig) {
                    hofArgs.push(t.objectExpression([
                        t.objectProperty(t.identifier('action'), t.stringLiteral(auditActionConfig.action))
                    ]));
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
      // Penting untuk traversal yang benar
      // if (declarationModified) path.skip(); else this.traverse(path);
    }
  });

  if (fileModified) {
    const outputOptions = { quote: 'single', trailingComma: true }; // Sesuaikan opsi printing
    const outputCode = recast.print(ast, outputOptions).code;
    fs.writeFileSync(filePath, outputCode, 'utf-8');
    console.log(`  [WRAP_HANDLERS] Successfully updated ${filePath}`);
  } else {
    // console.log(`  [WRAP_HANDLERS] No modifications needed for ${filePath}`);
  }
}

/**
 * Contoh sederhana untuk menentukan auditAction berdasarkan path dan method.
 * Ini perlu disesuaikan dengan kebutuhan spesifik Anda.
 * @param {string} filePath Path file API
 * @param {string} httpMethod Metode HTTP (GET, POST, dll.)
 * @returns {{ action: string } | null}
 */
function getAuditActionForRoute(filePath, httpMethod) {
    // Contoh: app/api/admin/users/[id]/route.ts
    // Jika method DELETE, action = 'admin_delete_user'
    // Jika method PUT, action = 'admin_update_user'
    const relativePath = path.relative(API_DIR, filePath);

    if (relativePath.startsWith('admin/users')) {
        if (httpMethod === 'POST' && !relativePath.includes('[id]')) return { action: 'admin_create_user' };
        if (relativePath.includes('[id]')) {
            if (httpMethod === 'PUT') return { action: 'admin_update_user' };
            if (httpMethod === 'DELETE') return { action: 'admin_delete_user' };
        }
    } else if (relativePath.startsWith('auth/login') && httpMethod === 'POST') {
        return { action: 'user_login_attempt' }; // Status sukses/gagal akan ditangani HOF
    } else if (relativePath.startsWith('auth/logout') && httpMethod === 'POST') {
        return { action: 'user_logout_attempt' };
    } else if (relativePath.startsWith('upload-pcap') && httpMethod === 'POST') {
        return { action: 'pcap_file_upload_attempt' };
    } else if (relativePath.startsWith('delete-pcap') && httpMethod === 'DELETE') {
        return { action: 'user_delete_single_analysis_attempt'};
    }
    // Tambahkan logika lain sesuai kebutuhan Anda
    return null; // Tidak ada audit action spesifik dari skrip ini
}


function walkDir(dir, callback) {
  fs.readdirSync(dir).forEach(f => {
    if (f === 'node_modules' || f === '.next' || f === '.vercel') return; // Hindari direktori ini
    const dirPath = path.join(dir, f);
    try {
        const stat = fs.statSync(dirPath);
        if (stat.isDirectory()) {
            walkDir(dirPath, callback);
        } else {
            callback(dirPath);
        }
    } catch (error) {
        // Abaikan error stat, mungkin symlink yang rusak atau file sementara
        // console.warn(`[WRAP_HANDLERS] Warning: Could not stat path ${dirPath}. Skipping. Error: ${error.message}`);
    }
  });
}

console.log('[WRAP_HANDLERS] Starting API handler wrapping process...');
try {
    walkDir(API_DIR, (filePath) => {
      if (filePath.endsWith('route.ts') || filePath.endsWith('route.js')) {
        if (filePath.includes('withApiLogging.ts') || filePath.includes('siem-logger.ts')) return;
        processFile(filePath);
      }
    });
} catch (error) {
    console.error("[WRAP_HANDLERS] Critical error during directory walk or processing:", error);
    process.exit(1); // Keluar dengan error code agar build Vercel gagal jika skrip ini error
}
console.log('[WRAP_HANDLERS] API handler wrapping process finished.');
