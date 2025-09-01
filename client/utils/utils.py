from platform import platform

def get_linux_device_model():
    try:
        with open("/sys/devices/virtual/dmi/id/product_name", "r") as f:
            model = f.readline().strip()
        with open("/sys/devices/virtual/dmi/id/sys_vendor", "r") as f:
            manufacturer = f.readline().strip()
        return manufacturer, model
    except Exception as e:
        return None, None

def get_device_name() -> str:
    manuf, _ = get_linux_device_model()
    return f"{manuf} {platform.system()} {platform.machine()}"