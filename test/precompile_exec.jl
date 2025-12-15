# Precompilation execution file for PackageCompiler
# This file exercises common code paths to improve startup time

using JAM

# Exercise the module's core functionality
println("Precompilation: exercising JAM module...")

# The actual CLI uses ArgParse, JSON, etc - those are loaded at runtime
# Here we just ensure the JAM module types are compiled

println("Precompilation execution complete")
