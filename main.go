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
	"log"
	"os"
	"text/template"

	"golang.org/x/tools/go/ast/astutil"
)

const tmpl = `
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
}
`

const src = `package foo

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

type variable struct {
	Name   string
	Values [][]string
}

func main() {
	fset := token.NewFileSet()

	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		log.Fatal(err)
	}

	key, nonce, aesgcm, err := setupAES()
	if err != nil {
		log.Fatal(err)
	}

	variables := make([]*variable, 0)
	astutil.Apply(f, func(c *astutil.Cursor) bool {
		switch typ := c.Node().(type) {
		case *ast.GenDecl:
			for _, spec := range typ.Specs {
				if vSpec, ok := spec.(*ast.ValueSpec); ok {
					for _, v := range vSpec.Values {
						obfuscated := &variable{Name: vSpec.Names[0].Name}
						switch real := v.(type) {
						case *ast.BasicLit:
							if real.Kind == token.STRING && len(real.Value) > 2 {
								obfuscated.Values = [][]string{bytesToHex(aesgcm.Seal(nil, nonce, []byte(real.Value[1:len(real.Value)-1]), nil))}
								variables = append(variables, obfuscated)
								// vSpec.Comment = &ast.CommentGroup{List: []*ast.Comment{{Text: " // " + real.Value}}} // doesn't work yet
								real.Value = `""`
							}
						case *ast.CompositeLit:
							for _, elt := range real.Elts {
								if inner, ok := elt.(*ast.BasicLit); ok && inner.Kind == token.STRING && len(inner.Value) > 2 {
									obfuscated.Values = append(obfuscated.Values, bytesToHex(aesgcm.Seal(nil, nonce, []byte(inner.Value[1:len(inner.Value)-1]), nil)))
								}
							}
							variables = append(variables, obfuscated)
							real.Elts = []ast.Expr{}
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
	if err != nil {
		log.Fatal(err)
	}

	vars, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	out := bufio.NewWriter(os.Stdout)

	out.WriteString(string(vars))

	tmpl, err := template.New("").Parse(tmpl)
	if err != nil {
		log.Fatal(err)
	}

	err = tmpl.Execute(out, struct {
		PrivateKey, Nonce []string
		Variables         []*variable
	}{
		PrivateKey: bytesToHex(key),
		Nonce:      bytesToHex(nonce),
		Variables:  variables,
	})
	if err != nil {
		log.Fatal(err)
	}

	out.Flush()
}

func setupAES() (key, nonce []byte, aesgcm cipher.AEAD, err error) {
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, nonce, aesgcm, nil
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
