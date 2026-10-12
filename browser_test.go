package main
import("os";"path/filepath";"testing";"net/http/httptest";"time")
func TestBrowserPreview(t *testing.T){dir:=os.Getenv("MIST_UI_PREVIEW_DIR");if dir==""{t.Skip("manual browser verification fixture")};a:=testApp(t);server:=httptest.NewTLSServer(a.routes());defer server.Close();if err:=os.WriteFile(filepath.Join(dir,"preview-url.txt"),[]byte(server.URL+"/test-panel/"),0600);err!=nil{t.Fatal(err)};for i:=0;i<600;i++{if _,err:=os.Stat(filepath.Join(dir,"preview-stop"));err==nil{return};time.Sleep(time.Second)};t.Fatal("preview deadline exceeded")}
