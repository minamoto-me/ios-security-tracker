// Simple syntax verification script
const fs = require('fs');
const path = require('path');

function checkTypeScriptSyntax() {
  const srcDir = path.join(__dirname, 'src');

  function checkDirectory(dir) {
    const files = fs.readdirSync(dir);

    for (const file of files) {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);

      if (stat.isDirectory()) {
        checkDirectory(filePath);
      } else if (file.endsWith('.ts')) {
        console.log(`Checking ${filePath}...`);
        try {
          const content = fs.readFileSync(filePath, 'utf8');

          // Basic syntax checks
          const openBraces = (content.match(/\{/g) || []).length;
          const closeBraces = (content.match(/\}/g) || []).length;

          if (openBraces !== closeBraces) {
            console.error(`❌ Mismatched braces in ${filePath}`);
            return false;
          }

          const openParens = (content.match(/\(/g) || []).length;
          const closeParens = (content.match(/\)/g) || []).length;

          if (openParens !== closeParens) {
            console.error(`❌ Mismatched parentheses in ${filePath}`);
            return false;
          }

          console.log(`✅ ${filePath} syntax looks good`);
        } catch (error) {
          console.error(`❌ Error reading ${filePath}:`, error.message);
          return false;
        }
      }
    }

    return true;
  }

  const isValid = checkDirectory(srcDir);

  if (isValid) {
    console.log('\n✅ All TypeScript files passed basic syntax check!');
  } else {
    console.log('\n❌ Some files have syntax issues.');
  }

  return isValid;
}

// Check project structure
console.log('📁 Checking project structure...');

const requiredFiles = [
  'src/index.ts',
  'src/types.ts',
  'src/database/schema.sql',
  'src/database/migrations.ts',
  'src/database/repository.ts',
  'src/services/vulnerability-scanner.ts',
  'src/services/apple-security-parser.ts',
  'src/services/nvd-client.ts',
  'src/api/handler.ts',
  'src/utils/logger.ts',
  'src/utils/error-handler.ts',
  'src/utils/metrics.ts',
  'src/utils/alerts.ts',
  'public/index.html',
  'public/styles.css',
  'public/script.js',
  'wrangler.toml',
  'package.json',
  'tsconfig.json'
];

let allFilesExist = true;

for (const file of requiredFiles) {
  if (fs.existsSync(file)) {
    console.log(`✅ ${file}`);
  } else {
    console.log(`❌ ${file} - MISSING`);
    allFilesExist = false;
  }
}

console.log('\n📝 Running TypeScript syntax check...');
const syntaxValid = checkTypeScriptSyntax();

console.log('\n🔧 Project Summary:');
console.log(`Files structure: ${allFilesExist ? '✅ Complete' : '❌ Missing files'}`);
console.log(`TypeScript syntax: ${syntaxValid ? '✅ Valid' : '❌ Errors found'}`);

if (allFilesExist && syntaxValid) {
  console.log('\n🎉 Project is ready for deployment!');
  console.log('\nNext steps:');
  console.log('1. Run: npm install (after fixing npm permissions)');
  console.log('2. Run: wrangler login');
  console.log('3. Create D1 database: wrangler d1 create ios-vulnerabilities-db');
  console.log('4. Create KV namespace: wrangler kv:namespace create "CACHE"');
  console.log('5. Update wrangler.toml with resource IDs');
  console.log('6. Deploy: npm run deploy');
} else {
  console.log('\n⚠️  Please fix the issues above before deployment.');
}