from flask import Flask, request, jsonify, render_template_string, abort, send_file
from pathlib import Path
from urllib.parse import unquote
from urllib.request import Request, urlopen
import json

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "data" / "public"
PRIVATE_DIR = BASE_DIR / "data" / "private"
app = Flask(__name__)

INDEX = r'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>KubMail — региональный архив</title><style>
body{margin:0;background:#f5efe3;color:#28251f;font:16px/1.5 Georgia,serif}.wrap{max-width:1000px;margin:auto;padding:28px}.top{display:flex;justify-content:space-between;border-bottom:3px solid #21613b;padding-bottom:14px}.logo{font-size:31px;font-weight:bold;color:#21613b}.badge{background:#f0be28;padding:5px 12px;border-radius:15px;font:13px Arial}.grid{display:grid;grid-template-columns:2fr 1fr;gap:22px;margin-top:24px}.card{background:#fffaf0;border:1px solid #d9ccb2;border-radius:12px;padding:20px;box-shadow:0 4px 0 #e5d7bd}.hero{background:#21613b;color:#fffaf0;border-radius:12px;padding:25px}.hero h1{margin:0 0 8px;font-size:29px}.card h2{color:#21613b}.links a{display:block;color:#21613b;text-decoration:none;padding:8px 0;border-bottom:1px dashed #c9b994}.links a:hover{text-decoration:underline}.small{font:13px Arial;color:#6c665b}.note{background:#fff2bf;padding:12px;border-left:4px solid #d49600;font:14px Arial}.mono{font:13px monospace;background:#eee6d5;padding:2px 5px}
</style></head><body><div class="wrap"><div class="top"><div class="logo">✉ KubMail</div><div class="badge">Краснодарский край • beta</div></div><div class="grid"><main><div class="hero"><h1>Почта, которая пахнет чернозёмом</h1><p>Региональный сервис справок, маршрутов и цифровых архивов Кубани.</p></div><div class="card"><h2>Публичные материалы</h2><div class="links"><a href="/download?name=welcome.txt">Приветственное письмо</a><a href="/download?name=tram_krd.txt">Трамвайная памятка Краснодара</a><a href="/download?name=recipe.txt">Рецепт настоящей кубанской аджики</a></div></div><div class="card"><h2>Проверка ссылки для предпросмотра</h2><p class="small">Функция временно скрыта из меню после обновления архивного шлюза.</p><p class="note">Подсказка для интеграторов: endpoint предпросмотра сохранён в API-документации.</p></div></main><aside><div class="card"><h2>Кубанский статус</h2><p>Краснодар: ясно, +27°C. Трамвай №7 следует по расписанию.</p><div class="links"><a href="/status">Статус системы</a><a href="/api/route?from=Вишняки&to=Аврора">Маршрутный помощник</a><a href="/api/docs">API-документация</a></div></div><div class="card"><h2>О проекте</h2><p class="small">KubMail использует старый архивный шлюз для совместимости с метеослужбой края.</p></div></aside></div></div></body></html>'''

@app.get('/')
def index(): return render_template_string(INDEX)

@app.get('/api/docs')
def docs():
    return jsonify({'name':'KubMail integration API','version':'2.3','endpoints':{'preview':'/api/preview?url=<URL>','route':'/api/route?from=&to='},'preview_note':'Preview accepts approved kubmail.local integration URLs.'})

@app.get('/api/preview')
def preview():
    target = request.args.get('url','')
    # Bug: allowlist is a substring check on the complete URL, not the effective host.
    if 'kubmail.local' not in target:
        return jsonify({'error':'destination is not on the approved integration network'}), 403
    try:
        # The proxy forwards requests to the URL supplied by the caller.
        # A real deployment would resolve kubmail.local through private DNS.
        req = Request(target, headers={'X-Kubmail-Proxy':'preview-v2','X-Forwarded-For':'10.23.7.14'})
        with urlopen(req, timeout=2) as response:
            body = response.read(8192).decode('utf-8', errors='replace')
            return jsonify({'status':response.status,'content_type':response.headers.get('Content-Type',''),'body':body})
    except Exception as exc:
        return jsonify({'error':'upstream unavailable','detail':str(exc)[:160]}), 502

@app.get('/api/route')
def route(): return jsonify({'from':request.args.get('from'),'to':request.args.get('to'),'line':'7','advice':'Не забудьте компостер: он любит порядок.'})

@app.get('/status')
def status(): return jsonify({'service':'KubMail','region':'Krasnodar Krai','version':'2.3.1-legacy','archive_adapter':'private-network gateway','preview':'/api/preview'})

@app.get('/download')
def download():
    name=request.args.get('name','')
    if not name or name.startswith('/') or '\\' in name or '..' in name: abort(403)
    target=PUBLIC_DIR / name
    if not target.is_file(): abort(404)
    return send_file(target,as_attachment=True,download_name=target.name)

@app.get('/internal/health')
def internal_health():
    if request.headers.get('X-Kubmail-Proxy') != 'preview-v2': abort(404)
    return jsonify({'service':'krd-archive-gateway','status':'ok','build':'2024.03.17','routes':'/internal/debug/routes','note':'legacy export requires a gateway ticket'})

@app.get('/internal/debug/routes')
def internal_debug():
    if request.headers.get('X-Kubmail-Proxy') != 'preview-v2': abort(404)
    return jsonify({'routes':['/internal/health','/internal/debug/routes','/internal/archive/export'],'export':{'method':'GET','ticket':'tram-7-archive','parameter':'name'},'warning':'debug route accidentally enabled in beta'})

@app.get('/internal/archive/export')
def internal_export():
    if request.headers.get('X-Kubmail-Proxy') != 'preview-v2': abort(404)
    if request.args.get('ticket') != 'tram-7-archive': return jsonify({'error':'invalid gateway ticket'}),401
    raw=request.args.get('name','')
    # Second legacy decoding layer: the gateway decodes after the proxy/WSGI layer.
    name=unquote(raw)
    target=(PUBLIC_DIR / name).resolve()
    if not target.is_file(): abort(404)
    return send_file(target,as_attachment=True,download_name=target.name)

@app.get('/about')
def about(): return 'KubMail — учебный сервис регионального цифрового архива.'

if __name__=='__main__': app.run(host='127.0.0.1',port=5000,debug=False)

