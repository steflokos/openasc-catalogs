import fs from "fs";
import Ajv from "ajv";
import addFormats from "ajv-formats";

const ajv = new Ajv({ allErrors: true, strict: true });
addFormats(ajv);

function load(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

/**
 * Validates a catalog file against its array schema, then pinpoint individual item issues.
 * @param {string} schemaPath - Path to the *-array.schema.json
 * @param {string} dataPath - Path to the data .json file
 * @param {string} arrayKey - The object property where the array lives ('threats', 'controls', 'assets')
 * @param {string} label - Human-readable label for logs
 */
function validateCatalog(schemaPath, dataPath, arrayKey, label) {
  const schema = load(schemaPath);
  const data = load(dataPath);

  // 1. Compile and validate the entire document structure (checks version, structure, etc.)
  const validateRoot = ajv.compile(schema);
  const isRootValid = validateRoot(data);

  // If the structure itself is broken (e.g. version missing), catch it early
  if (!isRootValid) {
    // Check if the error is just an item inside the array failing.
    // If it is, we will provide a much cleaner per-item breakdown below instead of crashing here.
    const hasOnlyArrayErrors = validateRoot.errors.every(err => err.instancePath.startsWith(`/${arrayKey}`));
    
    if (!hasOnlyArrayErrors) {
      console.error(`❌ [${label}] Global structure validation failed:`);
      console.error(validateRoot.errors);
      process.exitCode = 1;
      return;
    }
  }

  // 2. Extract the sub-schema for an individual item from the compilation tree
  const itemSchema = schema.properties?.[arrayKey]?.items;
  if (!itemSchema) {
    console.error(`❌ System Error: Could not isolate item definitions for property "${arrayKey}" in ${schemaPath}`);
    process.exitCode = 1;
    return;
  }

  // Compile individual item validator (inherits root $defs automatically)
  const validateItem = ajv.compile({
    $schema: schema.$schema,
    ...itemSchema,
    $defs: schema.$defs // Forward the definitions tree down
  });

  const targetArray = data[arrayKey] || [];
  let fileHasErrors = false;

  console.log(`\nChecking ${label} catalog (Version: ${data.version || "Unknown"})...`);

  // 3. Loop through individual items to pinpoint exact failures
  targetArray.forEach((item, index) => {
    const valid = validateItem(item);
    
    if (!valid) {
      fileHasErrors = true;
      const identifier = item.id || item.name || `Index ${index}`;
      
      console.error(`   ❌ Invalid Item: "${identifier}" (at ${arrayKey}[${index}])`);
      
      validateItem.errors.forEach(err => {
        const path = err.instancePath || "root";
        console.error(`      ⚠️  Path: ${path} | Message: ${err.message}`);
        if (err.params && Object.keys(err.params).length > 0) {
          console.error(`         Details:`, err.params);
        }
      });
    }
  });

  if (!fileHasErrors && isRootValid) {
    console.log(`   ✅ All ${targetArray.length} ${label.toLowerCase()} are perfectly valid!`);
  } else {
    process.exitCode = 1;
  }
}

// Target routing configuration mapping targets to schemas, data files, and internal object keys
const targets = {
  threats: { schema: "schemas/threat-array.schema.json", data: "threats/threats.json", key: "threats", label: "Threats" },
  controls: { schema: "schemas/control-array.schema.json", data: "controls/controls.json", key: "controls", label: "Controls" },
  assets: { schema: "schemas/asset-array.schema.json", data: "assets/assets.json", key: "assets", label: "Assets" }
};

const [targetArg] = process.argv.slice(2);

if (targets[targetArg]) {
  const t = targets[targetArg];
  validateCatalog(t.schema, t.data, t.key, t.label);
} else if (targetArg === "all") {
  Object.values(targets).forEach(t => {
    validateCatalog(t.schema, t.data, t.key, t.label);
  });
} else {
  console.log("Usage: node scripts/validate.js [threats|controls|assets|all]");
  process.exit(1);
}