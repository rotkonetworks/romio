using PackageCompiler

project_dir = dirname(dirname(@__FILE__))
build_dir = joinpath(project_dir, "build", "romio")
sysimage_path = joinpath(project_dir, "build", "romio.so")

# check if --app flag passed for standalone binary
build_app = "--app" in ARGS

if build_app
    println("Building romio standalone binary...")

    create_app(
        project_dir,
        build_dir,
        precompile_execution_file = joinpath(project_dir, "test", "precompile_exec.jl"),
        executables = ["romio" => "JAM.julia_main"],
        include_lazy_artifacts = true,
        force = true
    )

    println("Done: $build_dir/bin/romio")
    println("Run with: $build_dir/bin/romio")
else
    println("Building romio sysimage...")

    # create sysimage (faster builds, smaller size, requires julia runtime)
    create_sysimage(
        :JAM,
        sysimage_path = sysimage_path,
        precompile_execution_file = joinpath(project_dir, "test", "precompile_exec.jl"),
        include_transitive_dependencies = false
    )

    println("Done: $sysimage_path")
    println("Run with: julia -J$sysimage_path --project=. -e 'using JAM; JAM.main()'")
    println("\nFor standalone binary: julia --project=. build/build_app.jl --app")
end
