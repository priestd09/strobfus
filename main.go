package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"text/template"

	"golang.org/x/tools/go/ast/astutil"
)

func main() {
	fset := token.NewFileSet()

	src := `package foo

import (
	"crypto/aes"
	"crypto/cipher"
)

var hello string

var yolo = "poeut"
var arr = []string{
	"a",
	"b",
}

var (
	str1 = "coucou"
	arr1 = []string{
		"foo",
		"bar",
	}
	arr2 = []string{"h", "g"}

)
func init() {
}
`

	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		fmt.Println(err)
		return
	}

	values := make(map[string][][]byte)
	astutil.Apply(f, func(c *astutil.Cursor) bool {
		switch typ := c.Node().(type) {
		case *ast.GenDecl:
			for _, spec := range typ.Specs {
				if vSpec, ok := spec.(*ast.ValueSpec); ok {
					for _, v := range vSpec.Values {
						switch real := v.(type) {
						case *ast.BasicLit:
							if real.Kind == token.STRING {
								if len(real.Value) > 2 {
									values[vSpec.Names[0].Name] = [][]byte{[]byte(real.Value[1 : len(real.Value)-1])}
									// vSpec.Comment = &ast.CommentGroup{List: []*ast.Comment{{Text: " // " + real.Value}}} // doesn't work yet
									real.Value = `""`
								}
							}
						case *ast.CompositeLit:
							elts := make([][]byte, 0, len(real.Elts))
							for _, elt := range real.Elts {
								if inner, ok := elt.(*ast.BasicLit); ok && inner.Kind == token.STRING {
									if len(inner.Value) > 2 {
										elts = append(elts, []byte(inner.Value[1:len(inner.Value)-1]))
									}
								}
							}
							if len(elts) > 0 {
								values[vSpec.Names[0].Name] = elts
								real.Elts = []ast.Expr{}
							}
						}
					}
				}
			}
		case *ast.FuncDecl:
			if typ.Name.Name == "init" {
				c.Delete()
			}
		}
		return true
	}, nil)
	astutil.AddImport(fset, f, "crypto/aes")
	astutil.AddImport(fset, f, "crypto/cipher")

	config := &printer.Config{}
	var buf bytes.Buffer
	err = config.Fprint(&buf, fset, f)

	vars, err := format.Source(buf.Bytes())

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	for k, v := range values {
		array := make([][]byte, 0, len(v))
		for _, inner := range v {
			array = append(array, aesgcm.Seal(nil, nonce, inner, nil))
		}
		values[k] = array
	}

	out := bufio.NewWriter(os.Stdout)

	out.WriteString(string(vars))

	tmpl, err := template.New("").Parse(`
func init() {
	var __privateKeyObfuscator = []byte{
		{{- range .PrivateKey }}
		{{ . }}
		{{- end}}
	}
	var __nonceObfuscator = []byte{
		{{- range .Nonce }}
		{{ . }}
		{{- end}}
	}

	block, err := aes.NewCipher(__privateKeyObfuscator)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	{{- range .Variables }}
	{
		{{ if gt (len .Values) 1 -}}
		var __{{ .Name }} = [][]byte{
		{{- range $i, $e := .Values }}
			{
				{{- range $e }}
				{{ . }}
				{{- end}}
			},
		{{- end}}
		}
		ret := make([]string, 0, len(__{{ .Name }}))
		for _, v := range __{{ .Name }} {
			plaintext, err := aesgcm.Open(nil, __nonceObfuscator, v, nil)
			if err != nil {
				panic(err)
			}
			ret = append(ret, string(plaintext))
		}
		{{ .Name }} = ret
		{{- else -}}
		var __{{ .Name }} = []byte{
			{{- range ( index .Values 0) }}
			{{ . }}
			{{- end}}
		}
		plaintext, err := aesgcm.Open(nil, __nonceObfuscator, __{{ .Name }}, nil)
		if err != nil {
			panic(err)
		}
		{{ .Name }} = string(plaintext)
		{{- end }}
	}
	{{- end}}
}`)

	if err != nil {
		panic(err)
	}

	type variable struct {
		Name   string
		Values [][]string
	}

	variables := make([]variable, 0)
	for k, v := range values {
		if len(v) == 1 { //  string
			variables = append(variables, variable{Name: k, Values: [][]string{bytesToHex(v[0])}})
		} else {
			array := make([][]string, 0, len(v))
			for _, inner := range v {
				array = append(array, bytesToHex(inner))
			}
			variables = append(variables, variable{Name: k, Values: array})
		}
	}
	err = tmpl.Execute(out, struct {
		PrivateKey, Nonce []string
		Variables         []variable
	}{
		PrivateKey: bytesToHex(key),
		Nonce:      bytesToHex(nonce),
		Variables:  variables,
	})

	out.Flush()
}

func bytesToHex(value []byte) []string {
	ret := []string{}

	for len(value) > 0 {
		n := 16
		if n > len(value) {
			n = len(value)
		}

		s := ""
		for i, c := range value[:n] {
			if i == 0 {
				s += fmt.Sprintf("0x%02x,", c)
			} else {
				s += fmt.Sprintf(" 0x%02x,", c)
			}
		}
		ret = append(ret, s)
		value = value[n:]
	}
	return ret
}

// for _, decl := range f.Decls {
// 	if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.VAR {
// 		fmt.Printf("  var -> %+v\n", gen)
// 		for _, spec := range gen.Specs {
// 			if value, ok := spec.(*ast.ValueSpec); ok && value.Type == nil {
// 				fmt.Printf("   spec -> %+v\n", value)
// 				// value.Values = append(value.Values, &ast.BasicLit{Kind: token.STRING, Value: "toto"})
// 				for _, v := range value.Values {
// 					switch real := v.(type) {
// 					case *ast.BasicLit:
// 						if real.Kind == token.STRING {
// 							fmt.Printf("      string value -> %+v\n", real)
// 						}
// 					case *ast.CompositeLit:
// 						fmt.Printf("      composite value -> %+T\n", real.Type.(*ast.ArrayType).Elt)
// 						for _, elts := range real.Elts {
// 							fmt.Printf("        elts -> %+T\n", elts)
// 							if inner, ok := elts.(*ast.BasicLit); ok {
// 								fmt.Printf("          string value -> %+v\n", inner)
// 							}
// 						}
// 					default:
// 					}
// 				}
// 			} else {
// 				fmt.Printf("   WRONGSPEC -> %+v\n", value)
// 			}
// 		}
// 	} else {
// 		fmt.Printf("  UNKNOWN -> %+v\n", decl)
// 	}
// }
