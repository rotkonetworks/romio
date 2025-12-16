# Build script for creating standalone romio binary
using PackageCompiler

# Get the project root directory
project_dir = dirname(dirname(@__FILE__))
build_dir = joinpath(project_dir, "build", "romio")

println("Building romio standalone binary...")
println("Project directory: $project_dir")

# Clean build directory first
rm(build_dir, force=true, recursive=true)

# Create the app - julia_main is defined in JAM module
create_app(
    project_dir,
    build_dir,
    executables = ["romio" => "JAM.julia_main"],
    precompile_execution_file = joinpath(project_dir, "test", "precompile_exec.jl"),
    include_lazy_artifacts = true,
    include_transitive_dependencies = false,
    filter_stdlibs = true,
    force = true
)

println("Build complete!")
println("Binary located at: $(joinpath(build_dir, "bin", "romio"))")
