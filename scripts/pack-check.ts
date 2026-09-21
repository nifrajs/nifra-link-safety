import { readdir } from "node:fs/promises";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const packagesRoot = join(root, "packages");
const packageDirectories = await readdir(packagesRoot, { withFileTypes: true });

for (const directory of packageDirectories) {
  if (!directory.isDirectory()) continue;
  const packagePath = join(packagesRoot, directory.name, "package.json");
  const packageJson = await Bun.file(packagePath).json();
  if (typeof packageJson.name !== "string" || typeof packageJson.version !== "string") {
    throw new Error(`pack check: ${packagePath} missing name/version`);
  }
  if (packageJson.private === true) {
    throw new Error(`pack check: ${packageJson.name} is private`);
  }
  if (!packageJson.exports?.["."]?.import || !packageJson.exports?.["."]?.types) {
    throw new Error(`pack check: ${packageJson.name} missing ESM/type exports`);
  }
  if (!Array.isArray(packageJson.files) || !packageJson.files.includes("dist")) {
    throw new Error(`pack check: ${packageJson.name} must publish dist`);
  }
}

console.log(
  `pack check: ${packageDirectories.filter((entry) => entry.isDirectory()).length} packages valid`,
);
