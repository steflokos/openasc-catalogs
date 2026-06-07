import fs from "fs";
import path from "path";
import Ajv from "ajv";
import addFormats from "ajv-formats";

const ajv = new Ajv({ allErrors: true, strict: true });
addFormats(ajv);

// 1. Pre-load all standalone schemas into AJV cache so $ref matching works natively
const schemaDir = "schemas";
fs.readdirSync(schemaDir).forEach(file => {
  if (file.endsWith(".schema.json") && !file.includes("-array")) {
    const individualSchema = JSON.parse(fs.readFileSync(path.join(schemaDir, file), "utf-8"));
    // Use the filename as the schema ID key
    ajv.addSchema(individualSchema, file);
  }
});

function load(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

function validateCatalog(schemaPath, dataPath, arrayKey, label) {
  const schema = load(schemaPath);
  const data = load(dataPath);

  // Validate the overall file object structure (e.g., version formatting)
  const validateRoot = ajv.compile(schema);
  const isRootValid = validateRoot(data);

  if (!isRootValid) {
    const hasOnlyArrayErrors = validateRoot.errors.every(err => err.instancePath.startsWith(`/${arrayKey}`));
    if (!hasOnlyArrayErrors) {
      console.error(`❌ [${label}] Global structure validation failed:`);
      console.error(validateRoot.errors);
      process.exitCode = 1;
      return;
    }
  }

  // Fetch the schema validation rule directly out of the compiled root schema tree
  const itemSchemaRef = schema.properties?.[arrayKey]?.items;
  if (!itemSchemaRef) {
    console.error(`❌ System Error: Could not locate item reference definitions for property "${arrayKey}"`);
    process.exitCode = 1;
    return;
  }

  // Compile the validator for individual items using AJV's cache lookup
  const validateItem = ajv.compile(itemSchemaRef);
  const targetArray = data[arrayKey] || [];
  let fileHasErrors = false;

  console.log(`\nChecking ${label} catalog (Version: ${data.version || "Unknown"})...`);

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

// Configured targets pointing directly to your streamlined "catalogs/" data files
const targets = {
  threats: { schema: "schemas/threat-array.schema.json", data: "catalogs/threats.json", key: "threats", label: "Threats" },
  controls: { schema: "schemas/control-array.schema.json", data: "catalogs/controls.json", key: "controls", label: "Controls" },
  assets: { schema: "schemas/asset-array.schema.json", data: "catalogs/assets.json", key: "assets", label: "Assets" }
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