import modal

image = modal.Image.debian_slim().add_local_dir("SVF", remote_path="/root/SVF").apt_install(["cmake", "gcc", "g++", "libtinfo5", "libz-dev", "libzstd-dev", "zip", "wget", "libncurses5-dev"]).pip_install("numpy")

app = modal.App("example-get-started")


@app.function()
def square(x):
    print("This code is running on a remote worker!")
    return x**2


@app.local_entrypoint()
def main():
    print("the square is", square.remote(42))