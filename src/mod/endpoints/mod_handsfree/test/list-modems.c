#include <stdio.h>
#include <stdlib.h>
#include <dbus/dbus-glib.h>

int main(int argc, char *argv[])
{
	DBusGConnection *connection;
	GError *error;
	DBusGProxy *proxy;
	
	GValue *gentype;

	g_type_init();

	gentype = g_new0(GValue, 1);
	g_value_init(value, dbus_get_type_get_struct("GValueArray", G_TYPE_OBJECT, G_TYPE_ARRAY, G_TYPE_INVALID));

	error = NULL;
	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);

	if (!connection) {
		g_printerr("Failed to open connection to bus: %s\n", error->message);
		g_error_free(error);
		exit(1);
	}

	proxy = dbus_g_proxy_new_for_name(connection, 
					  "org.ofono",
					  "/",
					  "org.ofono.Manager");

	error = NULL;
	if (!dbus_g_proxy_call(proxy, "GetModems", &error, 
				G_TYPE_INVALID, DBUS_TYPE_G_UCHAR_ARRAY, 
				&gentype, G_TYPE_INVALID)) {
		if (error->domain == DBUS_GERROR && 
		    error->code == DBUS_GERROR_REMOTE_EXCEPTION) {
			g_printerr("Caught remote method exception %s: %s\n", 
					dbus_g_error_get_name(error), error->message);
		} else {
			g_printerr("Error: %s\n", error->message);
		}
		g_error_free(error);
		exit(1);
	}

	g_print("Modems: %d\n", gentype->len);

	//g_value_unset(&gentype);

	g_object_unref(proxy);

	exit(0);
}


