import platform

import qrcode
import distro

def get_linux_device_model():
    try:
        with open("/sys/devices/virtual/dmi/id/product_name", "r") as f:
            model = f.readline().strip()
        with open("/sys/devices/virtual/dmi/id/chassis_version", "r") as f:
            manufacturer = f.readline().strip()
        return manufacturer, model
    except Exception as e:
        return None, None


def get_device_name() -> str:
    manuf, model = get_linux_device_model()
    dis = distro.name(pretty=True)
    return f"{manuf} {model} - {dis} - {platform.machine()}"


def create_qr_code(token: str) -> None:
    """Crea e mostra un QR code dal token dato."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.show()


class Device:
    def __init__(self, device_name: str, main_device: bool = True, logged: bool = True):
        self.device_name = device_name
        self.main_device = main_device
        self.logged = logged

    def __str__(self):
        return f"{self.device_name}\nDipositivo Principale: {'Sì' if self.main_device else 'No'}\nOnline: {'Sì' if self.logged else 'No'}"

if __name__ == "__main__":
    print(get_device_name())