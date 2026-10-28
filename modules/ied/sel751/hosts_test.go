package sel751

import "testing"

func TestHosts(t *testing.T) {
	for _, id := range []string{"sel.id", "sel.ser.read_all", "sel.settings.show_global", "sel.settings.show_port1", "sel.config.read_all"} {
		if !Hosts(id) {
			t.Errorf("%s is not hosted", id)
		}
	}
	for _, id := range []string{"", "sel.config.read_other", "sel.settings.show_group_1", "sel.ser.clear"} {
		if Hosts(id) {
			t.Errorf("%q is hosted", id)
		}
	}
}
