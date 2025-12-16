using PackageCompiler

project_dir = dirname(dirname(@__FILE__))
build_dir = joinpath(project_dir, "build", "romio")
sysimage_path = joinpath(project_dir, "build", "romio.so")

println("Building romio sysimage...")

# Create sysimage instead of full app to avoid symlink issues
create_sysimage(
    :JAM,
    sysimage_path = sysimage_path,
    precompile_execution_file = joinpath(project_dir, "test", "precompile_exec.jl"),
    include_transitive_dependencies = false
)

println("Done: $sysimage_path")
println("Run with: julia -J$sysimage_path --project=. -e 'using JAM; JAM.main()'")
