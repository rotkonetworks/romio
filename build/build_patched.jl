using PackageCompiler
using Pkg

project_dir = dirname(dirname(@__FILE__))
build_dir = joinpath(project_dir, "build", "romio")

println("Building romio standalone binary...")
println("Project directory: $project_dir")
println("Build directory: $build_dir")

# Clean build directory
rm(build_dir, force=true, recursive=true)

# Use create_sysimage as an intermediate step
sysimage_path = joinpath(project_dir, "build", "romio_sysimage.so")

println("Creating sysimage...")
create_sysimage(
    :JAM,
    sysimage_path = sysimage_path,
    precompile_execution_file = joinpath(project_dir, "test", "precompile_exec.jl")
)

println("Sysimage created at: $sysimage_path")
