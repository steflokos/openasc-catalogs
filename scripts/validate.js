import fs from "fs";
import Ajv from "ajv";
import addFormats from "ajv-formats";

const ajv = new Ajv({ allErrors: true, strict: true });
addFormats(ajv);

function load(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

function validate(schemaPath, dataPath, label) {
  const schema = load(schemaPath);
  const data = load(dataPath);
  const validate = ajv.compile(schema);
  const valid = validate(data);

  if (valid) {
    console.log(`✅ ${label} are valid`);
  } else {
    console.error(`❌ ${label} are invalid:`);
    console.error(validate.errors);
    process.exitCode = 1;
  }
}

const [target] = process.argv.slice(2);

if (target === "threats") {
  validate("schemas/threat-array.schema.json", "threats/threats.json", "Threats");
} else if (target === "controls") {
  validate("schemas/control-array.schema.json", "controls/controls.json", "Controls");
} else if (target === "all") {
  validate("schemas/threat-array.schema.json", "threats/threats.json", "Threats");
  validate("schemas/control-array.schema.json", "controls/controls.json", "Controls");
} else {
  console.log("Usage: node scripts/validate.js [threats|controls|all]");
  process.exit(1);
}
