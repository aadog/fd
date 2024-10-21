using PInvoke.FridaCore;

namespace fd;

public static class Func
{
    public static FridaApplication? FindApplicationIdentifier(FridaDevice device,string identifier)
    {
        FridaApplication? selectApplication = null;
        var apps=device.EnumerateApplicationList(new FridaApplicationQueryOptions());
        foreach (var app in apps)
        {
            if (app.GetIdentifier() == identifier)
            {
                selectApplication = app;
            }
            else
            {
                Frida.GObjectUnRef(app.Handle);
            }
        }
        return selectApplication;
    }
    public static FridaApplication? FindApplication(FridaDevice device,string identifier)
    {
        FridaApplication? selectApplication = null;
        var apps=device.EnumerateApplicationList(new FridaApplicationQueryOptions());
        foreach (var app in apps)
        {
            if (app.GetName() == identifier)
            {
                selectApplication = app;
            }
            else
            {
                Frida.GObjectUnRef(app.Handle);
            }
        }
        return selectApplication;
    }
    public static FridaDevice? CheckAndConnectDevice(string? connectDevice,string? connectDeviceToken)
    {
        if (connectDevice != null)
        {
            if (connectDevice.ToLower() != "usb")
            {
                var options = new FridaRemoteDeviceOptions();
                if (connectDeviceToken != null)
                {
                    options.Token = connectDeviceToken;
                }
        
                return Global.DeviceManager.AddRemoteDevice(connectDevice,options);
            }
        }

        return null;
    }

    public static FridaDevice DeviceForDevi(string? devi)
    {
        if (devi==null)
        {
            var localDevice =Global.DeviceManager.FindDeviceByType(FridaDeviceType.FridaDeviceTypeLocal,1000);
            if (localDevice == null)
            {
                throw new Exception($"Local device not found");
            }

            return localDevice;
        }
        else
        {
            if (devi == "usb")
            {
                var usbDevice =Global.DeviceManager.FindDeviceByType(FridaDeviceType.FridaDeviceTypeUsb,1000);
                if (usbDevice == null)
                {
                    throw new Exception($"Usb device not found");
                }

                return usbDevice;
            }
            else
            {
                
                var remoteDevice = Global.DeviceManager.FindDeviceById($"socket@{devi}", 1000);
                if (remoteDevice== null)
                {
                    throw new Exception($"Remote device not found");
                }

                return remoteDevice;
            }
        }
    }
}