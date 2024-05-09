package main


import (

  "fmt"

  "text/template"
  "os"
  "io/ioutil"
  "strings"


)


func main(){


  var v1 string = fmt.Sprintf("%[2]d %[1]d\n", 11, 22)
    fmt.Printf("starting, %s", v1)

    opts :=make(map[string]interface{})

    opts["nodeID"] = "testNode"
    opts["cluster"]="testclusterID"
    opts["meta_json_str"]="json"

    dir, err := os.Getwd()
    	if err != nil {
    		panic(err)
    	}

    var filename string ="test.json"
    var outname string="out.json"


    if(!strings.Contains(dir, "cmd/envoy")){
      filename=dir+"/cmd/envoy/"+filename
      outname=dir+"/cmd/envoy/"+outname

    }


    cfgTmpl, err1 := ioutil.ReadFile(filename)
    if err1 != nil {
      panic (err1)
    } else {

          fout, err2 := os.Create(outname)
          if err2 != nil {
            panic (err2)
          }


          tmpl, err := template.New("test").Parse(string(cfgTmpl))
          if err != nil { panic(err) }
          err = tmpl.Execute(fout, opts)
          if err != nil {
             panic(err)
           } else {
             fmt.Printf(" output is created  %s \n", outname)

           }
    }

}
